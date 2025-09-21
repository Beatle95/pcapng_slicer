#include "pcapng_slicer/packet_private.h"

#include <cassert>
#include <cstdint>

namespace pcapng_slicer {

std::shared_ptr<InterfacePrivate> SimplePacketPrivate::GetInterface() const { return interface; }

uint32_t SimplePacketPrivate::GetOriginalLength() const { return original_length; }

uint64_t SimplePacketPrivate::GetTimestamp() const { return 0; }

std::span<const uint8_t> SimplePacketPrivate::GetData() const {
  assert(data.size() >= sizeof(uint32_t));
  return std::span<const uint8_t>(data.begin() + sizeof(uint32_t), data.end());
}

std::shared_ptr<InterfacePrivate> EnchansedPacketPrivate::GetInterface() const { return interface; }

uint32_t EnchansedPacketPrivate::GetOriginalLength() const { return original_length; }

uint64_t EnchansedPacketPrivate::GetTimestamp() const { return timestamp; }

std::span<const uint8_t> EnchansedPacketPrivate::GetData() const { return packet_data_slice; }

}  // namespace pcapng_slicer
