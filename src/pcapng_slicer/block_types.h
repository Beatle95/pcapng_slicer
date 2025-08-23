#pragma once

namespace pcapng_slicer {

enum class PcapngBlockType {
  kSectionHeader,
  kInterfaceDescription,
  kSimplePacket,
  kEnchancedPacket,
  kCustomBlock,
};

}  // namespace pcapng_slicer
