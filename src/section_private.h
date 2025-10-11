#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "pcapng_slicer/options.h"

namespace pcapng_slicer {

class InterfacePrivate;

class SectionPrivate {
 public:
  using InterfacesContainer = std::vector<std::shared_ptr<InterfacePrivate>>;

  size_t GetInterfaceCount() const;
  void PushInterface(std::shared_ptr<InterfacePrivate> interface);
  std::shared_ptr<InterfacePrivate> GetInterface(uint64_t index);
  const InterfacesContainer& Interfaces() const;

  Options ParseOptions() const;

  std::vector<uint8_t> data;

  uint64_t block_position;
  uint64_t section_length;
  uint32_t version_major;
  uint32_t version_minor;

 private:
  InterfacesContainer interfaces_;
};

}  // namespace pcapng_slicer
