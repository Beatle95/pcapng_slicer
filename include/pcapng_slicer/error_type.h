#pragma once

namespace pcapng_slicer {

enum class ErrorType {
  kNoError,
  kFileWasClosed,
  kFileNotFound,
  kUnableToOpenFile,
  kFileAlreadyExists,
  kFirstBlockIsNotSectionHeader,
  kInvalidBlockDetected,
  kTruncatedFile,
  kInvalidBlockSize,
  kInvalidInterfaceForPacket,
  kInvalidOptionSize,
  kWriteError,
};

}  // namespace pcapng_slicer
