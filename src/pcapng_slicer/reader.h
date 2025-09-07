#pragma once

#include <filesystem>
#include <memory>

#include "pcapng_slicer/error_type.h"
#include "pcapng_slicer/packet.h"

namespace pcapng_slicer {

class ScopedBlock;
class BlockReader;
class Section;
class Interface;

class Reader {
 public:
  // Tries to open file and returns true if file was opened successfully. Otherwise returns false
  // and more context of the error may be retrieved by GetState() function.
  bool Open(const std::filesystem::path& path);
  // Try read a packet, the returned value may be nullopt if we have reached the end of the file or
  // reading was imposible because an error has occured.
  std::optional<Packet> ReadPacket();
  // This function returns true if Open was successfully called and the Reader hasn't entered an
  // erroneus state.
  bool IsValid() const;
  // Return last error occured, if there was no error returns ErrorType::kNoError.
  ErrorType error() const { return last_error_; }

 private:
  using Sections = std::vector<std::shared_ptr<Section>>;

  void EnterErrorState(ErrorType error);

  std::optional<Packet> ReadPacketImpl();
  void ParseSectionHeaderIfNeeded(ScopedBlock& block);
  // TODO
  // void ParseInterface(std::vector<uint8_t> data);
  // void ParseSimplePacket(std::vector<uint8_t> data);
  // void ParseEnchansedPacket(std::vector<uint8_t> data);
  // void ParseCustomBlock(std::vector<uint8_t> data);

  std::unique_ptr<BlockReader> block_reader_;
  Sections sections_;
  ErrorType last_error_ = ErrorType::kNoError;
};

}  // namespace pcapng_slicer
