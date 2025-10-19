#pragma once

#include <cassert>
#include <span>
#include <type_traits>

namespace pcapng_slicer {

template <typename T>
T CastValue(std::span<const uint8_t> data) {
  static_assert(std::is_trivially_constructible_v<T>);
  assert(data.size() >= sizeof(T));
  return *reinterpret_cast<const uint32_t*>(&data[0]);
}

template <typename T>
T GetPaddingToOctet(T value) {
  static_assert(std::is_integral_v<T>);
  const auto tmp = value % sizeof(uint32_t);
  return tmp == 0 ? 0 : sizeof(uint32_t) - tmp;
}

}  // namespace pcapng_slicer
