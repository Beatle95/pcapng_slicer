#include "pcapng_slicer/reader.h"

#include <cassert>

#include "pcapng_slicer/block_reader.h"
#include "pcapng_slicer/block_types.h"
#include "pcapng_slicer/error.h"
#include "pcapng_slicer/error_type.h"

namespace pcapng_slicer {

bool Reader::Open(const std::filesystem::path& path) {
  try {
    last_error_ = ErrorType::kNoError;
    sections_.clear();
    block_reader_ = std::make_unique<BlockReader>(path);

    ScopedBlock block = block_reader_->ReadBlock();
    if (block.type() != static_cast<uint32_t>(PcapngBlockType::kSectionHeader)) {
      EnterErrorState(ErrorType::kFirstBlockIsNotSectionHeader);
      return false;
    }
    ParseSectionHeaderIfNeeded(block);
  } catch (const Error& e) {
    EnterErrorState(e.type());
    return false;
  }

  assert(!sections_.empty());
  return true;
}

std::optional<Packet> Reader::ReadPacket() {
  if (!block_reader_ || block_reader_->IsEof()) {
    return std::nullopt;
  }

  try {
    return ReadPacketImpl();
  } catch (const Error& e) {
    EnterErrorState(e.type());
    return std::nullopt;
  }
}

std::optional<Packet> Reader::ReadPacketImpl() {
  assert(block_reader_);

  ScopedBlock block = block_reader_->ReadBlock();
  switch (block.type()) {
    case static_cast<uint32_t>(PcapngBlockType::kSectionHeader):
      ParseSectionHeaderIfNeeded(block);
      break;
    case static_cast<uint32_t>(PcapngBlockType::kInterfaceDescription):
      // TODO
      break;
    case static_cast<uint32_t>(PcapngBlockType::kSimplePacket):
      // TODO
      break;
    case static_cast<uint32_t>(PcapngBlockType::kEnchancedPacket):
      // TODO
      break;
    case static_cast<uint32_t>(PcapngBlockType::kCustomBlock):
      // TODO
      break;
    default:
      EnterErrorState(ErrorType::kInvalidBlockDetected);
      break;
  }

  return std::nullopt;
}

void Reader::ParseSectionHeaderIfNeeded(ScopedBlock& block) {
  // TODO
}

bool Reader::IsValid() const { return !!block_reader_; }

void Reader::EnterErrorState(ErrorType error) {
  last_error_ = error;
  block_reader_.reset();
}

}  // namespace pcapng_slicer
