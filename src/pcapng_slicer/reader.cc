#include "pcapng_slicer/reader.h"

#include <cassert>

#include "pcapng_slicer/block_reader.h"
#include "pcapng_slicer/block_types.h"

namespace pcapng_slicer {

bool Reader::Open(const std::filesystem::path& path) {
  if (!std::filesystem::exists(path)) {
    state_ = State::kFileNotFound;
    return false;
  }

  block_reader_ = std::make_unique<BlockReader>(path);
  if (!block_reader_->IsValid()) {
    state_ = State::kFileOpenError;
    return false;
  }

  std::optional<BlockReader::Block> block = block_reader_->ReadBlock();
  if (!block.has_value() || block->type != static_cast<uint32_t>(PcapngBlockType::kSectionHeader)) {
    state_ = State::kInvalidFormat;
    return false;
  }

  current_section_ = ParseSectionHeader(block->data);
  if (!current_section_) {
    state_ = State::kInvalidFormat;
    return false;
  }

  state_ = State::kNormal;
  return true;
}

std::optional<Packet> Reader::ReadPacket() {
  if (state_ != State::kNormal) {
    return std::nullopt;
  }

  assert(block_reader_);
  assert(current_section_);

  // TODO
  return std::nullopt;
}

bool Reader::IsValid() const { return state_ == State::kNormal; }

Reader::State Reader::GetState() const { return state_; }

std::shared_ptr<Section> Reader::ParseSectionHeader(std::vector<uint8_t> data) {
  // TODO
  return {};
}

}  // namespace pcapng_slicer
