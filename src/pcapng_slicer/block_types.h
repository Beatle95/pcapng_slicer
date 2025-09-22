#pragma once

namespace pcapng_slicer {

enum class PcapngBlockType {
  kSectionHeader = 0x0A0D0D0A,
  kInterfaceDescription = 0x00000001,
  kSimplePacket = 0x00000003,
  kEnchancedPacket = 0x00000006,
  kCustomBlock1 = 0x00000BAD,
  kCustomBlock2 = 0x40000BAD,
};

}  // namespace pcapng_slicer
