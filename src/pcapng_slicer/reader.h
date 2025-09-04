#pragma once

#include <filesystem>
#include <memory>

#include "pcapng_slicer/packet.h"

namespace pcapng_slicer {

class ScopedBlock;
class BlockReader;
class Section;
class Interface;

class Reader {
 public:
  enum class State {
    kNormal,
    kNotOpened,
    kFileNotFound,
    kFileOpenError,
    kTruncatedFile,
    kInvalidFormat,
  };

  // Tries to open file and returns true if file was opened successfully. Otherwise returns false
  // and more context of the error may be retrieved by GetState() function.
  bool Open(const std::filesystem::path& path);
  // Try read a packet, the returned value may be nullopt if we have reached the end of the file or
  // reading was imposible because file was ill formated.
  std::optional<Packet> ReadPacket();
  // This function returns the state of the reader, it will only return false if file is ill
  // formated and we have encountered that damaged section during reading.
  bool IsValid() const;
  // This function is meant to show more information about current state of the reader, it is
  // intended to get more information about an error occured that was encountered during reading.
  State GetState() const;

 private:
  using Sections = std::vector<std::shared_ptr<Section>>;

  std::optional<Packet> ReadPacketImpl();
  void ParseSectionHeaderIfNeeded(ScopedBlock& block);
  // TODO
  // void ParseInterface(std::vector<uint8_t> data);
  // void ParseSimplePacket(std::vector<uint8_t> data);
  // void ParseEnchansedPacket(std::vector<uint8_t> data);
  // void ParseCustomBlock(std::vector<uint8_t> data);

  std::unique_ptr<BlockReader> block_reader_;
  Sections sections_;
  State state_ = State::kNotOpened;
};

}  // namespace pcapng_slicer
