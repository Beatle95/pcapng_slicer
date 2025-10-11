#include "pcapng_slicer/options.h"

namespace pcapng_slicer {

Options::Options() {}

Options::Options(std::span<const uint8_t> data) {
  // TODO
}

Options::Options(std::vector<Option> options, std::vector<CustomOption> custom_options)
    : options_(std::move(options)), custom_options_(std::move(custom_options)) {}

Options::~Options() = default;

Options::Options(const Options& other) = default;

Options& Options::operator=(const Options& other) = default;

Options::Options(Options&& other) = default;

Options& Options::operator=(Options&& other) = default;

const std::vector<Option>& Options::SimpleOptions() { return options_; }

const std::vector<CustomOption>& Options::CustomOptions() { return custom_options_; }

}  // namespace pcapng_slicer
