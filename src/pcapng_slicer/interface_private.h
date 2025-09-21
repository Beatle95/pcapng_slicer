#pragma once

#include <cstdint>

namespace pcapng_slicer {

class InterfacePrivate {
 public:
  uint32_t GetLinkType() const;
  uint32_t GetSnapLen() const;

 private:
  uint32_t link_type_;
  uint32_t snap_len_;
};

}  // namespace pcapng_slicer
