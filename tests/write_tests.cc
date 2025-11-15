#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include <filesystem>
#include <stdexcept>
#include <vector>

#include "doctest.h"
#include "pcapng_slicer/packet.h"
#include "pcapng_slicer/reader.h"
#include "pcapng_slicer/writer.h"
#include "test_config.h"

using namespace pcapng_slicer;

namespace {

const auto kTestOutputDir = std::filesystem::path(kTestOutputDirPath) / "test_output";

class TestDirectoryManager {
 public:
  explicit TestDirectoryManager(const std::filesystem::path& dir_path) : dir_path_(dir_path) {
    if (dir_path_.empty()) {
      throw std::runtime_error("Empty path for tests output directory is prohibited");
    }

    // Remove directory if it already exists and create new one.
    if (std::filesystem::exists(dir_path_)) {
      if (!std::filesystem::is_directory(dir_path_)) {
        throw std::runtime_error("Test directory path is not a directory");
      }
      std::filesystem::remove_all(dir_path_);
    }

    if (!std::filesystem::create_directories(dir_path_)) {
      throw std::runtime_error("Unable to create tests output directory");
    }
  }

  ~TestDirectoryManager() { std::filesystem::remove_all(dir_path_); }

  TestDirectoryManager(const TestDirectoryManager&) = default;
  TestDirectoryManager& operator=(const TestDirectoryManager&) = default;
  TestDirectoryManager(TestDirectoryManager&&) = delete;
  TestDirectoryManager& operator=(TestDirectoryManager&&) = delete;

 private:
  std::filesystem::path dir_path_;
};

std::vector<uint8_t> CreatePacketData(int packet_number) {
  const int packet_size = (packet_number + 1) % 100;
  std::vector<uint8_t> data(packet_size);
  for (int i = 0; i < packet_size; ++i) {
    data[i] = static_cast<uint8_t>(i % 256);
  }
  return data;
}

void VerifyWrittenPacket(const Packet& packet, int packet_number) {
  const auto data = packet.GetData();
  const int expected_size = (packet_number + 1) % 100;
  CHECK_EQ(data.size(), expected_size);

  for (int i = 0; i < data.size(); ++i) {
    CHECK_EQ(data[i], static_cast<uint8_t>(i % 256));
  }
  CHECK_EQ(packet.GetOriginalLength(), expected_size);
}

}  // namespace

TEST_CASE("Writing packets without options") {
  constexpr int kTotalPacketsCount = 500;
  TestDirectoryManager manager(kTestOutputDir);
  const std::filesystem::path test_file = kTestOutputDir / "write_test_no_options.pcapng";

  Writer writer;
  REQUIRE(writer.Open(test_file));
  CHECK(writer.IsValid());

  for (int i = 0; i < kTotalPacketsCount; ++i) {
    std::vector<uint8_t> packet_data = CreatePacketData(i);
    REQUIRE(writer.WritePacket(packet_data));
    CHECK(writer.IsValid());
  }

  writer.Close();
  CHECK_FALSE(writer.IsValid());

  // Now verify the written file can be read correctly.
  Reader reader;
  REQUIRE(reader.Open(test_file));
  CHECK(reader.IsValid());

  for (int i = 0; i < kTotalPacketsCount; ++i) {
    auto packet = reader.ReadPacket();
    REQUIRE_MESSAGE(packet.has_value(), std::format("Loop index was: {}", i));
    VerifyWrittenPacket(*packet, i);
  }
  CHECK_FALSE(reader.ReadPacket().has_value());
}

TEST_CASE("Writing empty packet") {
  TestDirectoryManager manager(kTestOutputDir);
  const std::filesystem::path test_file = kTestOutputDir / "write_test_empty_packet.pcapng";

  Writer writer;
  REQUIRE(writer.Open(test_file));
  std::vector<uint8_t> empty_packet;
  REQUIRE(writer.WritePacket(empty_packet));
  writer.Close();

  // Verify the written file can be read correctly.
  Reader reader;
  REQUIRE(reader.Open(test_file));

  auto packet = reader.ReadPacket();
  REQUIRE(packet.has_value());
  CHECK(packet->GetData().empty());
  CHECK_EQ(packet->GetOriginalLength(), 0);

  CHECK_FALSE(reader.ReadPacket().has_value());
}

TEST_CASE("Writing to non-existent directory fails") {
  TestDirectoryManager manager(kTestOutputDir);
  const std::filesystem::path test_file = kTestOutputDir / "non_existing_dir/test.pcapng";

  Writer writer;
  CHECK_FALSE(writer.Open(test_file));
  CHECK_EQ(writer.LastError(), ErrorType::kUnableToOpenFile);
}

TEST_CASE("Writing after closing file fails") {
  TestDirectoryManager manager(kTestOutputDir);
  const auto test_file = kTestOutputDir / "write_test_closed_file.pcapng";

  Writer writer;
  REQUIRE(writer.Open(test_file));
  auto packet_data = CreatePacketData(10);
  REQUIRE(writer.WritePacket(packet_data));

  writer.Close();

  // Try to write another packet after closing writer - should fail.
  auto packet_data2 = CreatePacketData(20);
  CHECK_FALSE(writer.WritePacket(packet_data2));
  CHECK_EQ(writer.LastError(), ErrorType::kFileWasClosed);
}
