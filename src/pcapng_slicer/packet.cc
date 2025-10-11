#include "pcapng_slicer/packet.h"

#include <cassert>

#include "pcapng_slicer/packet_private.h"

namespace pcapng_slicer {

Packet::Packet() = default;

Packet::Packet(std::unique_ptr<PacketPrivate> packet_impl) : packet_impl_(std::move(packet_impl)) {
  assert(packet_impl_);
}

Packet::Packet(Packet&& other) = default;

Packet& Packet::operator=(Packet&& other) = default;

Packet::~Packet() = default;

Interface Packet::GetInterface() const { return Interface(packet_impl_->GetInterface()); }

std::span<const uint8_t> Packet::GetData() const { return packet_impl_->GetData(); }

uint32_t Packet::GetOriginalLength() const { return packet_impl_->GetOriginalLength(); }

uint64_t Packet::GetTimestamp() const { return packet_impl_->GetTimestamp(); }

bool Packet::IsValid() const { return !!packet_impl_; }

Options Packet::ParseOptions() const {
  return packet_impl_ ? packet_impl_->ParseOptions() : Options{};
}

}  // namespace pcapng_slicer
