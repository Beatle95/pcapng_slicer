#pragma once

#include <exception>

#include "pcapng_slicer/error_type.h"

namespace pcapng_slicer {

class Error : public std::exception {
 public:
  explicit Error(ErrorType type) : type_(type) {}
  ~Error() override = default;
  ErrorType type() const { return type_; }

 private:
  ErrorType type_;
};

}  // namespace pcapng_slicer
