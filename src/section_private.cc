#include "section_private.h"

#include <cassert>

constexpr size_t kOptionsOffset = 4 * sizeof(uint32_t);

namespace pcapng_slicer {

size_t SectionPrivate::GetInterfaceCount() const { return interfaces_.size(); }

void SectionPrivate::PushInterface(std::shared_ptr<InterfacePrivate> interface) {
  interfaces_.push_back(std::move(interface));
}

std::shared_ptr<InterfacePrivate> SectionPrivate::GetInterface(uint64_t index) {
  assert(index < interfaces_.size());
  return interfaces_[index];
}

const SectionPrivate::InterfacesContainer& SectionPrivate::Interfaces() const {
  return interfaces_;
}

Options SectionPrivate::ParseOptions() const {
  if (data.size() < kOptionsOffset) {
    return Options{};
  }
  return Options(std::span<const uint8_t>(data.begin() + kOptionsOffset, data.end()));
}

}  // namespace pcapng_slicer
