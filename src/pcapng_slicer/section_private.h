#pragma once

#include <cstdint>
#include <memory>
#include <vector>

namespace pcapng_slicer {

class InterfacePrivate;

class SectionPrivate {
 public:
  using Interfaces = std::vector<std::shared_ptr<InterfacePrivate>>;

  void PushInterface(std::shared_ptr<InterfacePrivate> interface);
  size_t GetInterfaceCount() const;
  std::shared_ptr<InterfacePrivate> GetInterface(uint64_t index);

  uint64_t block_position() const { return block_position_; }
  const Interfaces& interfaces() const { return interfaces_; }

 private:
  Interfaces interfaces_;
  uint64_t block_position_;
};

}  // namespace pcapng_slicer
