#include "packet_private.h"

#include <cassert>
#include <cstdint>

namespace pcapng_slicer {

Options PacketPrivate::ParseOptions() const { return Options{}; }

std::shared_ptr<InterfacePrivate> SimplePacketPrivate::GetInterface() const { return interface; }

uint32_t SimplePacketPrivate::GetOriginalLength() const { return original_length; }

uint64_t SimplePacketPrivate::GetTimestamp() const { return 0; }

std::span<const uint8_t> SimplePacketPrivate::GetData() const {
  assert(interface);

  const auto real_length = std::min(original_length, interface->snap_len);
  assert(data.size() >= real_length + sizeof(uint32_t));

  return std::span<const uint8_t>(data.begin() + sizeof(uint32_t), real_length);
}

std::shared_ptr<InterfacePrivate> EnchansedPacketPrivate::GetInterface() const { return interface; }

uint32_t EnchansedPacketPrivate::GetOriginalLength() const { return original_length; }

uint64_t EnchansedPacketPrivate::GetTimestamp() const { return timestamp; }

std::span<const uint8_t> EnchansedPacketPrivate::GetData() const { return packet_data_slice; }

Options EnchansedPacketPrivate::ParseOptions() const { return Options(options_data_slice); }

}  // namespace pcapng_slicer
