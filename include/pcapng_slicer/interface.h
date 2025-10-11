#pragma once

#include <memory>

#include "pcapng_slicer/options.h"

namespace pcapng_slicer {

class InterfacePrivate;

class Interface {
 public:
  Interface();
  ~Interface();

  explicit Interface(std::shared_ptr<InterfacePrivate> interface);

  Interface(const Interface& other);
  Interface& operator=(const Interface& other);
  Interface(Interface&& other);
  Interface& operator=(Interface&& other);

  Options ParseOptions() const;

 private:
  std::shared_ptr<InterfacePrivate> interface_impl_;
};

}  // namespace pcapng_slicer
