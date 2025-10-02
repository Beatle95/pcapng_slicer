#pragma once

#include <cstdint>
#include <memory>
#include <vector>

namespace pcapng_slicer {

class InterfacePrivate;

class SectionPrivate {
 public:
  using Interfaces = std::vector<std::shared_ptr<InterfacePrivate>>;

  size_t GetInterfaceCount() const;
  void PushInterface(std::shared_ptr<InterfacePrivate> interface);
  std::shared_ptr<InterfacePrivate> GetInterface(uint64_t index);
  const Interfaces& interfaces() const { return interfaces_; }

  uint64_t block_position;
  uint64_t section_length;
  uint32_t version_major;
  uint32_t version_minor;

 private:
  Interfaces interfaces_;
};

}  // namespace pcapng_slicer
