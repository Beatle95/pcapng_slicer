#include "pcapng_slicer/reader.h"

#include <cassert>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "block_reader.h"
#include "block_types.h"
#include "error.h"
#include "interface_private.h"
#include "packet_private.h"
#include "pcapng_slicer/error_type.h"
#include "read_utils.h"
#include "section_private.h"

namespace pcapng_slicer {

Reader::Reader() = default;

Reader::~Reader() = default;

Reader::Reader(Reader&& other) = default;

Reader& Reader::operator=(Reader&& other) = default;

bool Reader::Open(const std::filesystem::path& path) {
  try {
    OpenImpl(path);
  } catch (const Error& e) {
    EnterErrorState(e.type());
    return false;
  }
  assert(section_);
  return true;
}

void Reader::OpenImpl(const std::filesystem::path& path) {
  last_error_ = ErrorType::kNoError;
  section_.reset();
  block_reader_ = std::make_unique<BlockReader>(path);

  ScopedBlock block = block_reader_->ReadBlock();
  if (block.type() != static_cast<uint32_t>(PcapngBlockType::kSectionHeader)) {
    // Must reset, because block_reader_ will be invalidated in EnterErrorState().
    throw Error(ErrorType::kFirstBlockIsNotSectionHeader);
  }

  ParseSectionHeader(block);
}

std::optional<Packet> Reader::ReadPacket() {
  if (!block_reader_ || block_reader_->IsEof()) {
    return std::nullopt;
  }
  try {
    do {
      if (std::unique_ptr<PacketPrivate> packet = ReadNextBlock()) {
        return std::make_optional<Packet>(std::move(packet));
      }
    } while (!block_reader_->IsEof() && last_error_ == ErrorType::kNoError);
    return std::nullopt;
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
      return nullptr;
    case static_cast<uint32_t>(PcapngBlockType::kInterfaceDescription):
      ParseInterface(block);
      return nullptr;
    case static_cast<uint32_t>(PcapngBlockType::kSimplePacket):
      return ParseSimplePacket(block);
    case static_cast<uint32_t>(PcapngBlockType::kEnchancedPacket):
      return ParseEnchansedPacket(block);
    default:
      // Ignore unkown blocks.
      return nullptr;
  }
}

//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                   Block Type = 0x0A0D0D0A                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                      Byte-Order Magic                         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |          Major Version        |         Minor Version         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |                                                               |
//    |                       Section Length                          |
//    |                                                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 24 /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
void Reader::ParseSectionHeader(ScopedBlock& block) {
  auto section = std::make_shared<SectionPrivate>();
  section->data = block.ReadData();

  std::span<const uint8_t> data_slice(section->data);
  if (data_slice.size() < 4 * sizeof(uint32_t)) {
    throw Error(ErrorType::kInvalidBlockSize);
  }

  section->block_position = block.position();
  section->version_major = CastValue<uint16_t>(data_slice.subspan(4));
  section->version_minor = CastValue<uint16_t>(data_slice.subspan(6));
  section->section_length = CastValue<uint64_t>(data_slice.subspan(8));

  section_ = std::move(section);
}

//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                    Block Type = 0x00000001                    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |           LinkType            |           Reserved            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                            SnapLen                            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
void Reader::ParseInterface(ScopedBlock& block) {
  assert(section_);
  auto interface = std::make_shared<InterfacePrivate>();
  interface->data = block.ReadData();

  std::span<const uint8_t> data_slice(interface->data);
  if (data_slice.size() < 2 * sizeof(uint32_t)) { 
    throw Error(ErrorType::kInvalidBlockSize);
  }

  interface->block_position = block.position();
  interface->link_type = CastValue<uint16_t>(data_slice);
  interface->snap_len = CastValue<uint32_t>(data_slice.subspan(4));
  
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
  packet->original_length = CastValue<uint32_t>(packet->data);
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
  if (packet_data_slice.size() < EnchansedPacketPrivate::kRequiredSize) {
    throw Error(ErrorType::kInvalidBlockSize);
  }

  const auto iface_id = CastValue<uint32_t>(packet_data_slice);
  if (iface_id >= section_->GetInterfaceCount()) {
    throw Error(ErrorType::kInvalidInterfaceForPacket);
  }
  packet->interface = section_->GetInterface(iface_id);

  uint64_t timestamp_high = CastValue<uint32_t>(packet_data_slice.subspan(4));
  uint64_t timestamp_low = CastValue<uint32_t>(packet_data_slice.subspan(8));
  packet->timestamp = (timestamp_high << 32 | timestamp_low);

  const uint32_t captured_length = CastValue<uint32_t>(packet_data_slice.subspan(12));
  packet->original_length = CastValue<uint32_t>(packet_data_slice.subspan(16));

  size_t real_length =
      std::min<size_t>(packet_data_slice.size() - EnchansedPacketPrivate::kRequiredSize,
                       std::min(captured_length, packet->interface->snap_len));
  packet->packet_data_slice =
      packet_data_slice.subspan(EnchansedPacketPrivate::kRequiredSize, real_length);
  packet->options_data_slice = packet_data_slice.subspan(
      EnchansedPacketPrivate::kRequiredSize + real_length + GetPaddingToOctet(real_length));

  return packet;
}

bool Reader::IsValid() const { return !!block_reader_ && last_error_ == ErrorType::kNoError; }

void Reader::EnterErrorState(ErrorType error) {
  last_error_ = error;
  block_reader_.reset();
}

}  // namespace pcapng_slicer
