#pragma once

#include <exception>

namespace pcapng_slicer {

class Error : public std::exception {
 public:
  enum class Type {
    kFileNotFound,
    kUnableToOpenFile,
    kTruncatedFile,
    kInvalidBlockSize,
  };

  explicit Error(Type type) : type_(type) {}
  ~Error() override = default;
  Type type() const { return type_; }

 private:
  Type type_;
};

}  // namespace pcapng_slicer
