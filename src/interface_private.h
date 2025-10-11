#pragma once

#include <cstdint>
#include <vector>

namespace pcapng_slicer {

struct InterfacePrivate {
  std::vector<uint8_t> data;
  uint64_t block_position;
  uint32_t link_type;
  uint32_t snap_len;
};

}  // namespace pcapng_slicer
