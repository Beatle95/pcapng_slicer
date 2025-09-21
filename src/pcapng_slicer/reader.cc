#include "pcapng_slicer/reader.h"

#include <cassert>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "pcapng_slicer/block_reader.h"
#include "pcapng_slicer/block_types.h"
#include "pcapng_slicer/error.h"
#include "pcapng_slicer/error_type.h"
#include "pcapng_slicer/interface_private.h"
#include "pcapng_slicer/packet_private.h"
#include "pcapng_slicer/section_private.h"

namespace pcapng_slicer {
namespace {

template <typename T>
uint32_t GetValue(std::span<const uint8_t> data) {
  assert(reinterpret_cast<uintptr_t>(data.data()) % 4 == 0);
  assert(data.size() >= sizeof(T));
  return *reinterpret_cast<const uint32_t*>(&data[0]);
}

}  // namespace

bool Reader::Open(const std::filesystem::path& path) {
  try {
    last_error_ = ErrorType::kNoError;
    section_.reset();
    block_reader_ = std::make_unique<BlockReader>(path);

    ScopedBlock block = block_reader_->ReadBlock();
    if (block.type() != static_cast<uint32_t>(PcapngBlockType::kSectionHeader)) {
      EnterErrorState(ErrorType::kFirstBlockIsNotSectionHeader);
      return false;
    }
    ParseSectionHeader(block);
  } catch (const Error& e) {
    EnterErrorState(e.type());
    return false;
  }

  assert(section_);
  return true;
}

std::optional<Packet> Reader::ReadPacket() {
  if (!block_reader_ || block_reader_->IsEof()) {
    return std::nullopt;
  }

  try {
    std::unique_ptr<PacketPrivate> packet;
    do {
      packet = ReadNextBlock();
    } while (!packet && !block_reader_->IsEof() && last_error_ == ErrorType::kNoError);
    return std::make_optional<Packet>(std::move(packet));
  } catch (const Error& e) {
    EnterErrorState(e.type());
    return std::nullopt;
  }
}

std::unique_ptr<PacketPrivate> Reader::ReadNextBlock() {
  assert(block_reader_);

  ScopedBlock block = block_reader_->ReadBlock();
  switch (block.type()) {
    case static_cast<uint32_t>(PcapngBlockType::kSectionHeader):
      ParseSectionHeader(block);
      return {};
    case static_cast<uint32_t>(PcapngBlockType::kInterfaceDescription):
      ParseInterface(block);
      return {};
    case static_cast<uint32_t>(PcapngBlockType::kSimplePacket):
      return ParseSimplePacket(block);
    case static_cast<uint32_t>(PcapngBlockType::kEnchancedPacket):
      return ParseEnchansedPacket(block);
    case static_cast<uint32_t>(PcapngBlockType::kCustomBlock):
      return {};
    default:
      // Ignore unkown blocks.
      return {};
  }
}

void Reader::ParseSectionHeader(ScopedBlock& block) {
  auto section = std::make_shared<SectionPrivate>();
  // TODO
  assert(section);
  section = std::move(section);
}

void Reader::ParseInterface(ScopedBlock& block) {
  assert(section_);
  auto interface = std::make_shared<InterfacePrivate>();
  // TODO
  assert(interface);
  section_->PushInterface(std::move(interface));
}

//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                    Block Type = 0x00000003                    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                    Original Packet Length                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 /                                                               /
//    /                          Packet Data                          /
//    /              variable length, padded to 32 bits               /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
std::unique_ptr<PacketPrivate> Reader::ParseSimplePacket(ScopedBlock& block) {
  assert(section_);
  size_t iface_count = section_->GetInterfaceCount();
  if (iface_count == 0) {
    throw Error(ErrorType::kInvalidInterfaceForPacket);
  }

  auto packet = std::make_unique<SimplePacketPrivate>();
  packet->interface = section_->GetInterface(0);
  packet->data = block.ReadData();
  if (packet->data.size() < sizeof(uint32_t)) {
    throw Error(ErrorType::kInvalidBlockSize);
  }
  packet->original_length = GetValue<uint32_t>(packet->data);
  return packet;
}

//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                    Block Type = 0x00000006                    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                         Interface ID                          |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                        Timestamp (High)                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |                        Timestamp (Low)                        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 20 |                    Captured Packet Length                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 24 |                    Original Packet Length                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 28 /                                                               /
//    /                          Packet Data                          /
//    /              variable length, padded to 32 bits               /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
std::unique_ptr<PacketPrivate> Reader::ParseEnchansedPacket(ScopedBlock& block) {
  assert(section_);
  auto packet = std::make_unique<EnchansedPacketPrivate>();
  packet->data = block.ReadData();

  std::span<const uint8_t> packet_data_slice(packet->data);
  if (packet_data_slice.size() < sizeof(uint32_t) * 5) {
    throw Error(ErrorType::kInvalidBlockSize);
  }

  const auto iface_id = GetValue<uint32_t>(packet_data_slice);
  if (iface_id >= section_->GetInterfaceCount()) {
    throw Error(ErrorType::kInvalidInterfaceForPacket);
  }
  packet->interface = section_->GetInterface(iface_id);

  uint64_t timestamp_high = GetValue<uint32_t>(packet_data_slice.subspan(4));
  uint64_t timestamp_low = GetValue<uint32_t>(packet_data_slice.subspan(8));
  packet->timestamp = (timestamp_high << 32 | timestamp_low);

  const uint32_t captured_length = GetValue<uint32_t>(packet_data_slice.subspan(12));
  packet->original_length = GetValue<uint32_t>(packet_data_slice.subspan(16));

  size_t real_length = std::min<size_t>(packet_data_slice.size() - 20,
                                        std::min(captured_length, packet->interface->GetSnapLen()));
  packet->packet_data_slice = packet_data_slice.subspan(20, real_length);

  // TODO: Options.

  return packet;
}

bool Reader::IsValid() const { return !!block_reader_ && last_error_ == ErrorType::kNoError; }

void Reader::EnterErrorState(ErrorType error) {
  last_error_ = error;
  block_reader_.reset();
}

}  // namespace pcapng_slicer
