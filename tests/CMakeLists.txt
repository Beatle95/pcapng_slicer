enable_testing()

# Generate test config file
set(PCAPNG_SLICER_TEST_RESOURCES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/resources")
configure_file(test_config.h.in test_config.h @ONLY)

add_executable(read_tests read_tests.cc)
target_link_libraries(read_tests PRIVATE pcapng_slicer)
target_include_directories(read_tests PRIVATE ${PROJECT_SOURCE_DIR}/third_party/doctest)
target_include_directories(read_tests PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
add_test(NAME read_tests COMMAND read_tests)
