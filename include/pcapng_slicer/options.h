#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "pcapng_slicer/export.h"

namespace pcapng_slicer {

// Single option representation.
class PCAPNG_SLICER_EXPORT Option {
 public:
  uint16_t GetCode() const;
  std::span<const uint8_t> GetRawData() const;
  std::optional<uint32_t> GetPenCode() const;
  
  bool IsString() const;
  std::string_view GetDataAsString() const;

 private:
  friend class Options;

  std::vector<uint8_t> data_;
  std::optional<uint32_t> pen_;
  uint16_t code_{};
};

// This class is simplel options container combined with the status of options parsing.
class PCAPNG_SLICER_EXPORT Options {
 public:
  using const_iterator = std::vector<Option>::const_iterator;

  Options();
  explicit Options(std::span<const uint8_t> data);
  ~Options();

  Options(const Options& other);
  Options& operator=(const Options& other);
  Options(Options&& other);
  Options& operator=(Options&& other);

  bool empty() const;
  size_t size() const;
  const Option* operator[](size_t index);
  const_iterator begin() const;
  const_iterator end() const;


 private:
  void ParseOptions(std::span<const uint8_t> data);

  std::vector<Option> options_;
};

}  // namespace pcapng_slicer
