#include "pcapng_slicer/packet.h"

#include "pcapng_slicer/packet_private.h"

namespace pcapng_slicer {

Packet::Packet(std::unique_ptr<PacketPrivate> packet_impl) : packet_impl_(std::move(packet_impl)) {}

Packet::~Packet() = default;

Interface Packet::GetInterface() const { return Interface(packet_impl_->GetInterface()); }

std::span<const uint8_t> Packet::GetData() const { return packet_impl_->GetData(); }

uint32_t Packet::GetOriginalLength() const { return packet_impl_->GetOriginalLength(); }

uint64_t Packet::GetTimestamp() const { return packet_impl_->GetTimestamp(); }

bool Packet::IsValid() const { return !!packet_impl_; }

}  // namespace pcapng_slicer
