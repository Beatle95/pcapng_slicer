#pragma once

#include <filesystem>
#include <fstream>
#include <memory>
#include <span>

#include "pcapng_slicer/error_type.h"
#include "pcapng_slicer/export.h"

// Forward declarations
namespace pcapng_slicer {
class SectionPrivate;
class InterfacePrivate;
}  // namespace pcapng_slicer

namespace pcapng_slicer {

class PCAPNG_SLICER_EXPORT Writer {
 public:
  Writer();
  ~Writer();

  Writer(const Writer&) = delete;
  Writer& operator=(const Writer&) = delete;
  Writer(Writer&& other);
  Writer& operator=(Writer&& other);

  // Tries to create a new file and returns true if file was created successfully. Otherwise returns
  // false and more context of the error may be retrieved by LastError() function.
  bool Open(const std::filesystem::path& path);

  // Closes currently opened file.
  void Close();

  // Writes a packet to the file and returns true if successful. Automatically adds Interface if
  // needed. Otherwise returns false and more context of the error may be retrieved by LastError()
  // function.
  bool WritePacket(std::span<const uint8_t> packet_data);

  // This function returns true if Create was successfully called and the Writer hasn't entered an
  // erroneous state.
  bool IsValid() const;

  // Return last error occurred, if there was no error returns ErrorType::kNoError.
  ErrorType LastError() const;

 private:
  void OpenImpl(const std::filesystem::path& path);
  void WriteSectionHeader();
  void WriteInterface();
  void WriteSimplePacket(std::span<const uint8_t> packet_data);
  void EnterErrorState(ErrorType error);

  std::ofstream file_;
  ErrorType last_error_ = ErrorType::kNoError;
};

}  // namespace pcapng_slicer
