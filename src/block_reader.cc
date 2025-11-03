#include "block_reader.h"

#include <cassert>
#include <cstdint>
#include <utility>
#include <vector>

#include "error.h"

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
  assert(!has_scoped_block_);

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

  ValidateTailLengthIfNeeded(length);
  ++block_position_;

  return data;
}

void BlockReader::SkipBlockData(uint32_t length) {
  if (!IsValid() || IsEof()) {
    return;
  }

  const uint32_t block_data_size = length - kEmptyBlockSize;
  file_.ignore(block_data_size);
  ValidateTailLengthIfNeeded(length);
  ++block_position_;
}

void BlockReader::ValidateTailLengthIfNeeded(uint32_t length) {
  assert(IsValid() && !IsEof());
  if (!validate_block_length_) {
    file_.ignore(sizeof(uint32_t));
    return;
  }

  const uint32_t tail_length = ReadAs<uint32_t>();
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
    : header_(header), block_position_(block_position), block_reader_(&block_reader) {
  assert(!std::exchange(block_reader_->has_scoped_block_, true) &&
         "Only one instance of ScopedBlock for a single BlockReader is allowed");
}

ScopedBlock::~ScopedBlock() {
  assert(!block_reader_ || std::exchange(block_reader_->has_scoped_block_, false));
  if (block_reader_ && block_reader_->IsValid()) {
    block_reader_->SkipBlockData(header_.total_length);
  }
}

uint32_t ScopedBlock::Length() const {
  assert(header_.total_length >= kEmptyBlockSize);
  return header_.total_length - kEmptyBlockSize;
}

std::vector<uint8_t> ScopedBlock::ReadData() {
  assert(block_reader_);
  std::vector<uint8_t> result = block_reader_->ReadBlockData(header_.total_length);
  PreventPostReading();
  return result;
}

void ScopedBlock::PreventPostReading() {
  assert(!block_reader_ || std::exchange(block_reader_->has_scoped_block_, false));
  block_reader_ = nullptr;
}

}  // namespace pcapng_slicer
