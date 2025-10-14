#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "pcapng_slicer/export.h"

namespace pcapng_slicer {

struct Option {
  std::vector<uint8_t> value;
  uint16_t code;
};

struct CustomOption {
  std::vector<uint8_t> value;
  uint32_t pen;
  uint16_t code;
};

class PCAPNG_SLICER_EXPORT Options {
 public:
  Options();
  explicit Options(std::span<const uint8_t> data);
  Options(std::vector<Option> options, std::vector<CustomOption> custom_options);
  ~Options();

  Options(const Options& other);
  Options& operator=(const Options& other);
  Options(Options&& other);
  Options& operator=(Options&& other);

  const std::vector<Option>& SimpleOptions();
  const std::vector<CustomOption>& CustomOptions();

 private:
  std::vector<Option> options_;
  std::vector<CustomOption> custom_options_;
};

}  // namespace pcapng_slicer
