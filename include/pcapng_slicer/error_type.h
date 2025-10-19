#pragma once

namespace pcapng_slicer {

enum class ErrorType {
  kNoError,
  kFileNotFound,
  kUnableToOpenFile,
  kFirstBlockIsNotSectionHeader,
  kInvalidBlockDetected,
  kTruncatedFile,
  kInvalidBlockSize,
  kInvalidInterfaceForPacket,
  kInvalidOptionSize,
};

}  // namespace pcapng_slicer
