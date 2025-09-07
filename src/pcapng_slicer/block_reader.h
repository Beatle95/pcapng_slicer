#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

#include "pcapng_slicer/error_type.h"

namespace pcapng_slicer {

class BlockReader;

struct BlockHeader {
  uint32_t type;
  uint32_t total_length;
};

// Block must never outlive it's BlockReader.
class ScopedBlock {
 public:
  ScopedBlock(BlockHeader header, uint64_t block_position, BlockReader& block_reader);
  ~ScopedBlock();
  ScopedBlock(const ScopedBlock&) = delete;
  ScopedBlock& operator=(const ScopedBlock&) = delete;
  ScopedBlock(ScopedBlock&&) = delete;
  ScopedBlock& operator=(ScopedBlock&&) = delete;

  uint32_t Length() const;
  std::vector<uint8_t> ReadData();

  uint64_t position() const { return block_position_; }
  uint32_t type() const { return header_.type; }

 private:
  uint64_t block_position_;
  BlockHeader header_;
  BlockReader* block_reader_;
  bool data_read_performed_ = false;
};

// This class is responsible for reading blocks from a file. It will position itself over the start
// of the block and will provide to the user the main info about the block. It responsibility of the
// caller to parse block contents.
class BlockReader {
 public:
  BlockReader(const std::filesystem::path& path);

  ScopedBlock ReadBlock();
  bool IsEof() const;
  bool IsValid() const;

 private:
  friend class ScopedBlock;

  BlockHeader ReadBlockHeader();
  std::vector<uint8_t> ReadBlockData(uint32_t length);
  void SkipBlockData(uint32_t length);
  void ValidateTailLength(uint32_t length);
  void CloseAndThrow(ErrorType type);

  template <typename T>
  T ReadIntegral();

  mutable std::ifstream file_;
  uint64_t block_position_ = 0;
};

}  // namespace pcapng_slicer
