#include "pcapng_slicer/writer.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <filesystem>

#include "block_types.h"
#include "error.h"
#include "pcapng_slicer/error_type.h"
#include "read_utils.h"

namespace pcapng_slicer {
namespace {

constexpr std::array<char, 4> kPaddingBytes = {0, 0, 0, 0};
constexpr uint32_t kByteOrderMagic = 0x0A0D0D0A;
constexpr uint16_t kEthernetLinkType = 1;
constexpr uint16_t kPacketLengthIsNotLimited = 0;

struct SectionHeader {
  uint32_t block_type;
  uint32_t block_total_length_leading;
  uint32_t byte_order_magic;
  uint16_t major_version;
  uint16_t minor_version;
  uint64_t section_length;
  uint32_t block_total_length_trailing;
};

struct InterfaceHeader {
  uint32_t block_type;
  uint32_t block_total_length_leading;
  uint16_t link_type;
  uint16_t reserved;
  uint32_t snap_len;
  uint32_t block_total_length_trailing;
};

}  // namespace

Writer::Writer() = default;

Writer::~Writer() {
  if (file_.is_open()) {
    file_.close();
  }
}

Writer::Writer(Writer&& other) : file_(std::move(other.file_)), last_error_(other.last_error_) {
  other.last_error_ = ErrorType::kNoError;
}

Writer& Writer::operator=(Writer&& other) {
  if (this != &other) {
    file_ = std::move(other.file_);
    last_error_ = other.last_error_;
    other.last_error_ = ErrorType::kNoError;
  }
  return *this;
}

bool Writer::Open(const std::filesystem::path& path) {
  last_error_ = ErrorType::kNoError;

  try {
    OpenImpl(path);
    return true;
  } catch (const Error& err) {
    EnterErrorState(err.type());
    return false;
  }
}

void Writer::Close() {
  if (file_.is_open()) {
    file_.close();
  }
}

bool Writer::WritePacket(std::span<const uint8_t> packet_data) {
  if (!file_.is_open() && last_error_ == ErrorType::kNoError) {
    last_error_ = ErrorType::kFileWasClosed;
  }
  if (!file_.is_open() || last_error_ != ErrorType::kNoError) {
    return false;
  }

  try {
    WriteSimplePacket(packet_data);
    return true;
  } catch (const std::exception&) {
    EnterErrorState(ErrorType::kInvalidBlockDetected);
    return false;
  }
}

bool Writer::IsValid() const { return file_.is_open() && last_error_ == ErrorType::kNoError; }

ErrorType Writer::LastError() const { return last_error_; }

void Writer::OpenImpl(const std::filesystem::path& path) {
  if (std::filesystem::exists(path)) {
    throw Error(ErrorType::kFileAlreadyExists);
  }

  file_.open(path, std::ios::binary | std::ios::out);
  if (!file_.is_open()) {
    throw Error(ErrorType::kUnableToOpenFile);
  }

  WriteSectionHeader();
  WriteInterface();
}

void Writer::WriteSectionHeader() {
  static_assert(sizeof(SectionHeader) == 32);
  SectionHeader header{
      .block_type = static_cast<uint32_t>(PcapngBlockType::kSectionHeader),
      .block_total_length_leading = sizeof(SectionHeader),
      .byte_order_magic = kByteOrderMagic,
      .major_version = 1,
      .minor_version = 0,
      .section_length = 0xFFFFFFFFFFFFFFFF,
      .block_total_length_trailing = sizeof(SectionHeader),
  };

  file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
  if (!file_.good()) {
    throw Error(ErrorType::kWriteError);
  }
}

void Writer::WriteInterface() {
  static_assert(sizeof(InterfaceHeader) == 20);
  InterfaceHeader header{
      .block_type = static_cast<uint32_t>(PcapngBlockType::kInterfaceDescription),
      .block_total_length_leading = sizeof(InterfaceHeader),
      .link_type = kEthernetLinkType,
      .reserved = 0,
      .snap_len = kPacketLengthIsNotLimited,
      .block_total_length_trailing = sizeof(InterfaceHeader),
  };

  file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
  if (!file_.good()) {
    throw Error(ErrorType::kWriteError);
  }
}

void Writer::WriteSimplePacket(std::span<const uint8_t> packet_data) {
  const uint32_t block_type = static_cast<uint32_t>(PcapngBlockType::kSimplePacket);
  const uint32_t original_length = packet_data.size();
  const uint32_t padding = GetPaddingToOctet(packet_data.size());
  const uint32_t block_total_length = 4 * sizeof(uint32_t) + packet_data.size() + padding;

  file_.write(reinterpret_cast<const char*>(&block_type), sizeof(block_type));
  file_.write(reinterpret_cast<const char*>(&block_total_length), sizeof(block_total_length));
  file_.write(reinterpret_cast<const char*>(&original_length), sizeof(original_length));
  file_.write(reinterpret_cast<const char*>(packet_data.data()), packet_data.size());

  // Write padding bytes if needed.
  if (padding > 0) {
    file_.write(kPaddingBytes.data(), padding);
  }

  // And trailing block length.
  file_.write(reinterpret_cast<const char*>(&block_total_length), sizeof(block_total_length));

  if (!file_.good()) {
    throw Error(ErrorType::kInvalidBlockDetected);
  }
}

void Writer::EnterErrorState(ErrorType error) {
  last_error_ = error;
  if (file_.is_open()) {
    file_.close();
  }
}

}  // namespace pcapng_slicer
