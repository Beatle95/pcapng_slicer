#include "pcapng_slicer/section_private.h"

#include <cassert>

namespace pcapng_slicer {

void SectionPrivate::PushInterface(std::shared_ptr<InterfacePrivate> interface) {
  interfaces_.push_back(std::move(interface));
}

size_t SectionPrivate::GetInterfaceCount() const { return interfaces_.size(); }

std::shared_ptr<InterfacePrivate> SectionPrivate::GetInterface(uint64_t index) {
  assert(index < interfaces_.size());
  return interfaces_[index];
}

}  // namespace pcapng_slicer
