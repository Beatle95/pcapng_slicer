#pragma once

#include <cstdint>
#include <span>
#include <memory>

// TODO
#include "pcapng_slicer/interface_private.h"

namespace pcapng_slicer {

class PacketPrivate;
class Interface;

// TODO: Move this class to separate file.
class Interface {
 public:
  Interface();
  explicit Interface(std::shared_ptr<InterfacePrivate> interface);
};

class Packet {
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

 private:
  std::unique_ptr<PacketPrivate> packet_impl_;
};

}  // namespace pcapng_slicer
