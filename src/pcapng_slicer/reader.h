#pragma once

#include <filesystem>
#include <memory>

#include "pcapng_slicer/packet.h"

namespace pcapng_slicer {

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
  // This function is meant to show more information about an error that was encountered during
  // reading.
  State GetState() const;

 private:
  std::shared_ptr<Section> ParseSectionHeader(std::vector<uint8_t> data);

  std::unique_ptr<BlockReader> block_reader_;
  std::shared_ptr<Section> current_section_;
  State state_ = State::kNotOpened;
};

}  // namespace pcapng_slicer
