#include "pcapng_slicer/interface.h"
#include <span>

#include "pcapng_slicer/interface_private.h"

constexpr size_t kOptionsOffset = 2 * sizeof(uint32_t);

namespace pcapng_slicer {

Interface::Interface() = default;

Interface::~Interface() = default;

Interface::Interface(std::shared_ptr<InterfacePrivate> interface)
    : interface_impl_(std::move(interface)) {}

Interface::Interface(const Interface& other) = default;

Interface& Interface::operator=(const Interface& other) = default;

Interface::Interface(Interface&& other) = default;

Interface& Interface::operator=(Interface&& other) = default;

Options Interface::ParseOptions() const {
  if (!interface_impl_ || interface_impl_->data.size() < kOptionsOffset) {
    return Options{};
  }
  return Options(std::span<const uint8_t>(interface_impl_->data).subspan(kOptionsOffset));
}

}  // namespace pcapng_slicer
