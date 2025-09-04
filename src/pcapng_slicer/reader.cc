#include "pcapng_slicer/reader.h"

#include <cassert>

#include "pcapng_slicer/block_reader.h"
#include "pcapng_slicer/block_types.h"
#include "pcapng_slicer/error.h"

namespace pcapng_slicer {
namespace {

Reader::State ErrorTypeToState(Error::Type type) {
  switch (type) {
    case Error::Type::kFileNotFound:
      return Reader::State::kFileNotFound;
    case Error::Type::kUnableToOpenFile:
      return Reader::State::kFileOpenError;
    case Error::Type::kTruncatedFile:
      return Reader::State::kTruncatedFile;
    case Error::Type::kInvalidBlockSize:
      return Reader::State::kInvalidFormat;
  }
}

}  // namespace

bool Reader::Open(const std::filesystem::path& path) {
  try {
    block_reader_ = std::make_unique<BlockReader>(path);
    ScopedBlock block = block_reader_->ReadBlock();
    if (block.type() != static_cast<uint32_t>(PcapngBlockType::kSectionHeader)) {
      state_ = State::kInvalidFormat;
      return false;
    }
    ParseSectionHeaderIfNeeded(block);
  } catch (const Error& e) {
    state_ = ErrorTypeToState(e.type());
    return false;
  }

  assert(!sections_.empty());
  state_ = State::kNormal;
  return true;
}

std::optional<Packet> Reader::ReadPacket() {
  if (state_ != State::kNormal) {
    return std::nullopt;
  }

  try {
    return ReadPacketImpl();
  } catch (const Error& e) {
    state_ = ErrorTypeToState(e.type());
    return std::nullopt;
  }

  return std::nullopt;
}

bool Reader::IsValid() const { return state_ == State::kNormal; }

Reader::State Reader::GetState() const { return state_; }

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
      state_ = State::kInvalidFormat;
      break;
  }

  return std::nullopt;
}

void Reader::ParseSectionHeaderIfNeeded(ScopedBlock& block) {
  // TODO
}

}  // namespace pcapng_slicer
