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

  const BlockHeader header = ReadBlockHeader();
  if (header.total_length % kBlockAlignment != 0 || header.total_length < kEmptyBlockSize) {
    CloseAndThrow(ErrorType::kInvalidBlockSize);
  }

  return ScopedBlock(header, block_position_, *this);
}

bool BlockReader::IsEof() const {
  assert(IsValid());
  return file_.eof() || file_.peek() == std::char_traits<char>::eof();
}

bool BlockReader::IsValid() const { return !!file_; }

BlockHeader BlockReader::ReadBlockHeader() {
  static_assert(sizeof(BlockHeader) == 8, "BlockHeader must be 8 bytes long");
  BlockHeader result = ReadAs<BlockHeader>();
  return result;
}

std::vector<uint8_t> BlockReader::ReadBlockData(uint32_t length) {
  assert(IsValid() && !IsEof());
  assert(length >= kEmptyBlockSize);

  const size_t block_data_size = length - kEmptyBlockSize;
  std::vector<uint8_t> data(block_data_size);
  file_.read(reinterpret_cast<char*>(data.data()), block_data_size);
  if (file_.gcount() != block_data_size) {
    CloseAndThrow(ErrorType::kTruncatedFile);
  }

  ValidateTailLength(length);
  ++block_position_;

  return data;
}

void BlockReader::SkipBlockDataIfInsideBlock(uint32_t length) {
  if (!IsValid() || IsEof()) {
    return;
  }

  const uint32_t block_data_size = length - kEmptyBlockSize;
  file_.ignore(block_data_size);
  ValidateTailLength(length);
  ++block_position_;
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
  file_.close();
  throw Error{type};
}

template <typename T>
T BlockReader::ReadAs() {
  static_assert(std::copy_constructible<T>, "T must be an copyt constructible type");
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
  if (block_reader_ && block_reader_->IsValid()) {
    block_reader_->SkipBlockDataIfInsideBlock(header_.total_length);
  }
}

uint32_t ScopedBlock::Length() const {
  assert(header_.total_length >= kEmptyBlockSize);
  return header_.total_length - kEmptyBlockSize;
}

std::vector<uint8_t> ScopedBlock::ReadData() {
  assert(block_reader_);
  auto result = block_reader_->ReadBlockData(header_.total_length);
  block_reader_ = nullptr;
  return result;
}

void ScopedBlock::Reset() { block_reader_ = nullptr; }

}  // namespace pcapng_slicer
