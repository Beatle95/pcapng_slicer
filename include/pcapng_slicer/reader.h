#pragma once

#include <filesystem>
#include <memory>

#include "pcapng_slicer/error_type.h"
#include "pcapng_slicer/export.h"
#include "pcapng_slicer/packet.h"

namespace pcapng_slicer {

class BlockReader;
class ScopedBlock;
class SectionPrivate;
class Interface;
class PacketPrivate;

class PCAPNG_SLICER_EXPORT Reader {
 public:
  Reader();
  ~Reader();

  Reader(const Reader&) = delete;
  Reader& operator=(const Reader&) = delete;
  Reader(Reader&& other);
  Reader& operator=(Reader&& other);

  // Tries to open file and returns true if file was opened successfully. Otherwise returns false
  // and more context of the error may be retrieved by LastError() function.
  bool Open(const std::filesystem::path& path);
  // TODO: Add an explicit Close() function.
  // Try read a packet, the returned value may be nullopt if we have reached the end of the file or
  // reading was imposible because an error has occured. If result is non-nullopt, then the packet
  // is guaranteed to be valid.
  std::optional<Packet> ReadPacket();
  // This function returns true if Open was successfully called and the Reader hasn't entered an
  // erroneus state.
  bool IsValid() const;
  // Return last error occured, if there was no error returns ErrorType::kNoError.
  ErrorType LastError() const { return last_error_; }

 private:
  void OpenImpl(const std::filesystem::path& path);
  void EnterErrorState(ErrorType error);

  // Reads next block and optionally returns a packet, if this type of block war red.
  std::unique_ptr<PacketPrivate> ReadNextBlock();
  void ParseSectionHeader(ScopedBlock& block);
  void ParseInterface(ScopedBlock& block);
  std::unique_ptr<PacketPrivate> ParseSimplePacket(ScopedBlock& block);
  std::unique_ptr<PacketPrivate> ParseEnchansedPacket(ScopedBlock& block);

  std::unique_ptr<BlockReader> block_reader_;
  std::shared_ptr<SectionPrivate> section_;
  ErrorType last_error_ = ErrorType::kNoError;
};

}  // namespace pcapng_slicer
