#pragma once

#include <cstdint>

namespace pcapng_slicer {

struct InterfacePrivate {
  uint64_t block_position;
  uint32_t link_type;
  uint32_t snap_len;
};

}  // namespace pcapng_slicer
