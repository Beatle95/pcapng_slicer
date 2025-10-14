#pragma once

#include <cstdint>
#include <memory>
#include <span>

#include "pcapng_slicer/export.h"
#include "pcapng_slicer/interface.h"

namespace pcapng_slicer {

class PacketPrivate;
class Interface;

class PCAPNG_SLICER_EXPORT Packet {
 public:
  Packet();
  ~Packet();
  explicit Packet(std::unique_ptr<PacketPrivate> packet_impl);
  
  Packet(const Packet&) = delete;
  Packet& operator=(const Packet&) = delete;
  Packet(Packet&& other);
  Packet& operator=(Packet&& other);

  Interface GetInterface() const;
  std::span<const uint8_t> GetData() const;
  uint32_t GetOriginalLength() const;
  uint64_t GetTimestamp() const;
  bool IsValid() const;

  Options ParseOptions() const;

 private:
  std::unique_ptr<PacketPrivate> packet_impl_;
};

}  // namespace pcapng_slicer
