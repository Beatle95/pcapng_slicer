#pragma once

#include <sys/types.h>

#include <filesystem>
#include <fstream>
#include <optional>

namespace pcapng_slicer {

// This class is responsible for reading blocks from a file. It will position itself over the start
// of the block and will provide to the user the main info about the block. It responsibility of the
// caller to parse block contents.
class BlockReader {
 public:
  enum class State { kNormal, kErrorOccured };
  struct Block {
    uint32_t type;
    std::vector<uint8_t> data;
  };

  BlockReader(const std::filesystem::path& path);

  std::optional<Block> ReadBlock();
  bool IsEof() const;
  bool IsValid() const;

 private:
  struct BlockHeader {
    uint32_t type;
    uint32_t total_length;
  };

  template <typename T>
  std::optional<T> ReadIntegral();
  std::optional<BlockHeader> ReadBlockHeader();

  mutable std::ifstream file_;
  State state_ = State::kNormal;
};

}  // namespace pcapng_slicer
