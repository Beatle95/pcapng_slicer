#include "pcapng_slicer/block_reader.h"

#include <cassert>
#include <cstdint>

constexpr size_t kBlockAlignment = 4;
constexpr size_t kEmptyBlockSize = 12;

namespace pcapng_slicer {

BlockReader::BlockReader(const std::filesystem::path& path) {
  assert(std::filesystem::exists(path));
  file_.open(path, std::ios::binary);
  if (!file_) {
    state_ = State::kErrorOccured;
  }
}

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
std::optional<BlockReader::Block> BlockReader::ReadBlock() {
  if (state_ != State::kNormal || IsEof()) {
    return std::nullopt;
  }

  const std::optional<BlockHeader> header = ReadBlockHeader();
  if (!header.has_value()) {
    state_ = State::kErrorOccured;
    return std::nullopt;
  }

  if (header->total_length % kBlockAlignment != 0 || header->total_length < kEmptyBlockSize) {
    state_ = State::kErrorOccured;
    return std::nullopt;
  }

  static_assert(sizeof(BlockHeader) == 8, "BlockHeader must be 8 bytes long");
  const size_t block_data_size = header->total_length - kEmptyBlockSize;
  std::vector<uint8_t> data(block_data_size);
  file_.read(reinterpret_cast<char*>(data.data()), block_data_size);
  if (file_.gcount() != block_data_size) {
    state_ = State::kErrorOccured;
    return std::nullopt;
  }

  uint32_t preamble_size = 0;
  file_.read(reinterpret_cast<char*>(&preamble_size), sizeof(preamble_size));
  if (file_.gcount() != sizeof(preamble_size) || preamble_size != header->total_length) {
    state_ = State::kErrorOccured;
    return std::nullopt;
  }

  return Block{header->type, std::move(data)};
}

bool BlockReader::IsEof() const { return file_.peek() == std::char_traits<char>::eof(); }

bool BlockReader::IsValid() const { return state_ == State::kNormal; }

template <typename T>
std::optional<T> BlockReader::ReadIntegral() {
  static_assert(std::is_integral<T>::value, "T must be an integral type");
  assert(!!file_);

  T value;
  file_.read(reinterpret_cast<char*>(&value), sizeof(T));
  return file_.gcount() == sizeof(T) ? std::make_optional(value) : std::nullopt;
}

std::optional<BlockReader::BlockHeader> BlockReader::ReadBlockHeader() {
  const auto type = ReadIntegral<uint32_t>();
  if (!type.has_value() || !file_) {
    return std::nullopt;
  }

  const auto length = ReadIntegral<uint32_t>();
  if (!length.has_value() || !file_) {
    return std::nullopt;
  }

  return BlockHeader{type.value(), length.value()};
}

}  // namespace pcapng_slicer
