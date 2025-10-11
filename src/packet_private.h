#pragma once

#include <sys/types.h>

#include <span>
#include <vector>

#include "interface_private.h"
#include "pcapng_slicer/options.h"

namespace pcapng_slicer {

class PacketPrivate {
 public:
  virtual ~PacketPrivate() = default;

  virtual std::shared_ptr<InterfacePrivate> GetInterface() const = 0;
  virtual std::span<const uint8_t> GetData() const = 0;
  virtual uint32_t GetOriginalLength() const = 0;
  virtual uint64_t GetTimestamp() const = 0;
  virtual Options ParseOptions() const;
};

class SimplePacketPrivate : public PacketPrivate {
 public:
  // PacketPrivate overrides:
  std::shared_ptr<InterfacePrivate> GetInterface() const override;
  uint32_t GetOriginalLength() const override;
  uint64_t GetTimestamp() const override;
  std::span<const uint8_t> GetData() const override;

  std::shared_ptr<InterfacePrivate> interface;
  std::vector<uint8_t> data;
  uint32_t original_length;
};

class EnchansedPacketPrivate : public PacketPrivate {
 public:
  static constexpr size_t kRequiredSize = 5 * sizeof(uint32_t);

  // PacketPrivate overrides:
  std::shared_ptr<InterfacePrivate> GetInterface() const override;
  uint32_t GetOriginalLength() const override;
  uint64_t GetTimestamp() const override;
  std::span<const uint8_t> GetData() const override;
  Options ParseOptions() const override;

  std::shared_ptr<InterfacePrivate> interface;

  std::vector<uint8_t> data;
  std::span<const uint8_t> packet_data_slice;
  std::span<const uint8_t> options_data_slice;

  uint32_t original_length;
  uint64_t timestamp;
};

}  // namespace pcapng_slicer
