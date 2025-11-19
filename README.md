# pcapng_slicer

A C++ library for parsing and writing pcapng (PCAP Next Generation) files. This library provides a simple API for reading and writing network packet capture files in the pcapng format. Library mostly complete, but lacks of some writing capabilities. Any PRs are welcome.

## Features

- Read and write pcapng files
- Simple API for packet manipulation
- Cross-platform compatibility
- CMake integration support
- Tested on macOS

## Building and installation

To build the library, use the standard CMake workflow:

```bash
cmake -S --install-prefix={path_to_install_dir} {path_to_source_dir} -B {path_to_build_dir} 
cmake --build {path_to_build_dir}
cmake --install {path_to_build_dir}
```

You can use next cmake configuration options:

- `PCAPNG_SLICER_SHARED_LIBS` - Build the shared library
- `PCAPNG_SLICER_BUILD_TESTS` - Build the tests

```bash
cmake -DPCAPNG_SLICER_SHARED_LIBS=ON -DPCAPNG_SLICER_BUILD_TESTS=ON -S {path_to_source_dir} -B {path_to_build_dir}
```

## Using in your CMake project

To use pcapng_slicer in your CMake project, first find the package and then link it to your target:

```cmake
find_package(pcapng_slicer REQUIRED)

# For your executable or library
target_link_libraries(your_target PRIVATE pcapng_slicer)
```

## Usage

### Reading pcapng files

Here's a simple example of how to read packets from a pcapng file:

```cpp
#include <iostream>
#include <pcapng_slicer/reader.h>

int main() {
    pcapng_slicer::Reader reader;
    
    if (!reader.Open("example.pcapng")) {
        std::cerr << "Failed to open file" << std::endl;
        return 1;
    }
    
    while (auto packet = reader.ReadPacket()) {
        std::cout << "Packet size: " << packet->GetData().size() << " bytes" << std::endl;
        std::cout << "Original length: " << packet->GetOriginalLength() << " bytes" << std::endl;
        
        // Process packet data
        auto data = packet->GetData();
        // ... your packet processing code here ...
    }
    
    if (reader.LastError() != pcapng_slicer::ErrorType::kNoError) {
        std::cerr << "Error reading file" << std::endl;
        return 1;
    }
    
    return 0;
}
```

### Writing pcapng files

Here's a simple example of how to write packets to a pcapng file:

```cpp
#include <iostream>
#include <vector>
#include <pcapng_slicer/writer.h>

int main() {
    pcapng_slicer::Writer writer;
    
    if (!writer.Open("output.pcapng")) {
        std::cerr << "Failed to create file" << std::endl;
        return 1;
    }
    
    // Create some sample packet data
    std::vector<uint8_t> packet_data = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    if (!writer.WritePacket(packet_data)) {
        std::cerr << "Failed to write packet" << std::endl;
        return 1;
    }
    
    // Write more packets as needed...
    
    // Close the file
    writer.Close();
    
    return 0;
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
