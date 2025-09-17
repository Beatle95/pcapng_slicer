#include "pcapng_slicer/block_reader.h"

#include <cassert>
#include <cstdint>
#include <vector>

#include "pcapng_slicer/error.h"

constexpr uint32_t kBlockAlignment = 4;
constexpr uint32_t kEmptyBlockSize = 12;

namespace pcapng_slicer {

// Block layout.
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                          Block Type                           |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 /                          Block Body                           /
//    /              variable length, padded to 32 bits               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

BlockReader::BlockReader(const std::filesystem::path& path) {
  if (!std::filesystem::exists(path)) {
    CloseAndThrow(ErrorType::kFileNotFound);
  }
  file_.open(path, std::ios::binary);
  if (!file_) {
    CloseAndThrow(ErrorType::kUnableToOpenFile);
  }
}

ScopedBlock BlockReader::ReadBlock() {
  assert(IsValid() && !IsEof());
  assert(!inside_block_);

  const BlockHeader header = ReadBlockHeader();
  if (header.total_length % kBlockAlignment != 0 || header.total_length < kEmptyBlockSize) {
    CloseAndThrow(ErrorType::kInvalidBlockSize);
  }

  inside_block_ = true;
  return ScopedBlock(header, block_position_, *this);
}

bool BlockReader::IsEof() const { return file_.peek() == std::char_traits<char>::eof(); }

bool BlockReader::IsValid() const { return !!file_; }

BlockHeader BlockReader::ReadBlockHeader() {
  const auto type = ReadIntegral<uint32_t>();
  const auto length = ReadIntegral<uint32_t>();
  return BlockHeader{type, length};
}

std::vector<uint8_t> BlockReader::ReadBlockData(uint32_t length) {
  static_assert(sizeof(BlockHeader) == 8, "BlockHeader must be 8 bytes long");
  assert(IsValid() && !IsEof());
  assert(length >= kEmptyBlockSize);
  assert(inside_block_);

  const size_t block_data_size = length - kEmptyBlockSize;
  std::vector<uint8_t> data(block_data_size);
  file_.read(reinterpret_cast<char*>(data.data()), block_data_size);
  if (file_.gcount() != block_data_size) {
    CloseAndThrow(ErrorType::kTruncatedFile);
  }

  ValidateTailLength(length);
  ++block_position_;
  inside_block_ = false;

  return data;
}

void BlockReader::SkipBlockDataIfInsideBlock(uint32_t length) {
  assert(IsValid() && !IsEof());
  if (inside_block_) {
    return;
  }

  const uint32_t block_data_size = length - kEmptyBlockSize;
  file_.ignore(block_data_size);
  ValidateTailLength(length);
  ++block_position_;
  inside_block_ = false;
}

void BlockReader::ValidateTailLength(uint32_t length) {
  assert(IsValid() && !IsEof());
  uint32_t tail_length = 0;
  file_.read(reinterpret_cast<char*>(&tail_length), sizeof(tail_length));
  if (file_.gcount() != sizeof(tail_length)) {
    CloseAndThrow(ErrorType::kTruncatedFile);
  }
  if (tail_length != length) {
    CloseAndThrow(ErrorType::kInvalidBlockSize);
  }
}

void BlockReader::CloseAndThrow(ErrorType type) {
  inside_block_ = false;
  file_.close();
  throw Error{type};
}

template <typename T>
T BlockReader::ReadIntegral() {
  static_assert(std::is_integral<T>::value, "T must be an integral type");
  assert(!!file_);

  T value;
  file_.read(reinterpret_cast<char*>(&value), sizeof(T));
  if (file_.gcount() != sizeof(T)) {
    CloseAndThrow(ErrorType::kTruncatedFile);
  }
  return value;
}

ScopedBlock::ScopedBlock(BlockHeader header, uint64_t block_position, BlockReader& block_reader)
    : header_(header), block_position_(block_position), block_reader_(&block_reader) {}

ScopedBlock::~ScopedBlock() {
  assert(block_reader_);
  if (!block_reader_->IsValid()) {
    return;
  }
  block_reader_->SkipBlockDataIfInsideBlock(header_.total_length);
}

uint32_t ScopedBlock::Length() const {
  assert(header_.total_length >= kEmptyBlockSize);
  return header_.total_length - kEmptyBlockSize;
}

std::vector<uint8_t> ScopedBlock::ReadData() {
  assert(block_reader_);
  return block_reader_->ReadBlockData(header_.total_length);
}

}  // namespace pcapng_slicer
