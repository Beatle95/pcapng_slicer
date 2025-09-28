#pragma once

#include <cstdint>

namespace pcapng_slicer {

class InterfacePrivate {
 public:
  uint32_t ling_type() const { return link_type_;}
  uint32_t snap_len() const { return snap_len_; }

 private:
  uint32_t link_type_;
  uint32_t snap_len_ = 1'000'000;
};

}  // namespace pcapng_slicer
