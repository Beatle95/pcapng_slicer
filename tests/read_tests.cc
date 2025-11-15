#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include <filesystem>
#include <string>

#include "doctest.h"
#include "pcapng_slicer/packet.h"
#include "pcapng_slicer/reader.h"
#include "test_config.h"

using namespace pcapng_slicer;

namespace {

const auto kTestFileWithoutOptions =
    std::filesystem::path(kTestResourcesDirPath) / "no_options.pcapng";
const auto kTestFileWithOptions =
    std::filesystem::path(kTestResourcesDirPath) / "with_options.pcapng";
constexpr std::string_view kExpectedComment = "abcdefghijklmnopqrstuvwxyz";

void VerifyPacket(const Packet& packet, int packet_number, bool has_options) {
  const auto data = packet.GetData();
  CHECK_EQ(data.size(), packet_number + 1);
  for (int i = 0; i < data.size(); ++i) {
    CHECK_EQ(data[i], i);
  }
  CHECK_EQ(packet.GetOriginalLength(), packet_number + 2);

  if (!has_options) {
    CHECK(packet.ParseOptions().empty());
    return;
  }

  Options packet_options = packet.ParseOptions();
  const auto comment_len = packet_number % (kExpectedComment.size() + 1);
  if (comment_len == 0) {
    CHECK(packet_options.empty());
    return;
  }

  const std::string num_message = std::format("Packet number was: {}", packet_number);
  REQUIRE_MESSAGE(packet_options.size() == 1, num_message);
  const Option* opt = packet_options[0];
  REQUIRE(opt != nullptr);
  CHECK(opt->IsString());
  CHECK_MESSAGE(opt->GetDataAsString() == kExpectedComment.substr(0, comment_len), num_message);
}

}  // namespace

// TODO: Reading non-opened file returns error.

TEST_CASE("Reading without options") {
  Reader reader;
  REQUIRE(reader.Open(kTestFileWithoutOptions));

  for (int i = 0; i < 100; ++i) {
    auto packet = reader.ReadPacket();
    REQUIRE(packet.has_value());
    VerifyPacket(*packet, i, /*has_options=*/false);
  }

  CHECK_FALSE(reader.ReadPacket().has_value());
  CHECK(reader.IsValid());
}

TEST_CASE("Reading with options") {
  Reader reader;
  REQUIRE(reader.Open(kTestFileWithOptions));
  // TODO: Check file options.

  for (int i = 0; i < 100; ++i) {
    auto packet = reader.ReadPacket();
    REQUIRE(packet.has_value());
    VerifyPacket(*packet, i, /*has_options=*/true);
  }

  CHECK_FALSE(reader.ReadPacket().has_value());
  CHECK(reader.IsValid());
}
