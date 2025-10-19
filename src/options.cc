#include "pcapng_slicer/options.h"

#include <array>
#include <cstdint>
#include <vector>

#include "error.h"
#include "pcapng_slicer/error_type.h"
#include "read_utils.h"

constexpr uint16_t kEndofopt = 0;
constexpr uint16_t kOptComment = 1;
constexpr auto kCustomCodes = std::to_array({2988, 2989, 19372, 19373});

namespace pcapng_slicer {
namespace {
std::vector<uint8_t> GetOptionBody(std::span<const uint8_t> data, uint32_t length) {
  if (data.size() < length) {
    throw Error(ErrorType::kInvalidOptionSize);
  }
  return std::vector<uint8_t>(data.begin(), data.begin() + length);
}
}  // namespace

Options::Options() {}

Options::Options(std::span<const uint8_t> data) {
  try {
    ParseOptions(data);
  } catch (const Error&) {
    // TODO: Save en error to notify the user about it.
  }
}

Options::~Options() = default;

Options::Options(const Options& other) = default;

Options& Options::operator=(const Options& other) = default;

Options::Options(Options&& other) = default;

Options& Options::operator=(Options&& other) = default;

bool Options::empty() const { return options_.empty(); }

size_t Options::size() const { return options_.size(); }

Options::const_iterator Options::begin() const { return options_.begin(); }

Options::const_iterator Options::end() const { return options_.end(); }

const Option* Options::operator[](size_t index) {
  if (index >= options_.size()) {
    return nullptr;
  }
  return &options_[index];
}

// General options structure.
//                      1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Option Code              |         Option Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                       Option Value                            /
// /              variable length, padded to 32 bits               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                 . . . other options . . .                     /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Option Code == opt_endofopt |   Option Length == 0          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Custom option.
//                      1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Custom Option Code        |         Option Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                Private Enterprise Number (PEN)                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                        Custom Data                            /
// /              variable length, padded to 32 bits               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
void Options::ParseOptions(std::span<const uint8_t> data) {
  while (!data.empty()) {
    if (data.size() < 2 * sizeof(uint16_t)) {
      throw Error(ErrorType::kInvalidOptionSize);
    }

    const auto code = CastValue<uint16_t>(data);
    const auto length = CastValue<uint16_t>(data.subspan(2));
    if (code == kEndofopt) {
      break;
    }

    Option new_option;
    new_option.code_ = code;
    data = data.subspan(2 * sizeof(uint16_t));
    if (std::ranges::find(kCustomCodes, code) == kCustomCodes.end()) {
      new_option.data_ = GetOptionBody(data, length);
    } else {
      if (data.size() < sizeof(uint32_t)) {
        throw Error(ErrorType::kInvalidOptionSize);
      }
      new_option.pen_ = CastValue<uint32_t>(data);
      data = data.subspan(sizeof(uint32_t));
      new_option.data_ = GetOptionBody(data, length);
    }
    options_.push_back(std::move(new_option));

    data = data.subspan(length + GetPaddingToOctet(length));
  }
}

uint16_t Option::GetCode() const { return code_; }

std::span<const uint8_t> Option::GetRawData() const { return data_; }

std::optional<uint32_t> Option::GetPenCode() const { return pen_; }

bool Option::IsString() const { return code_ == kOptComment; }

std::string_view Option::GetDataAsString() const {
  return std::string_view(reinterpret_cast<const char*>(data_.data()), data_.size());
}

}  // namespace pcapng_slicer
