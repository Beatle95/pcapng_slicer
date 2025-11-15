enable_testing()

# Generate test config file.
set(PCAPNG_SLICER_TEST_RESOURCES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/resources")
set(PCAPNG_SLICER_TEST_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
configure_file(test_config.h.in test_config.h @ONLY)

function(create_pcapng_test test_name)
  add_executable(${test_name} ${ARGN})
  target_link_libraries(${test_name} PRIVATE pcapng_slicer)
  target_include_directories(
    ${test_name} PRIVATE ${PROJECT_SOURCE_DIR}/third_party/doctest
                         ${CMAKE_CURRENT_BINARY_DIR})
  add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

create_pcapng_test(read_tests read_tests.cc)
create_pcapng_test(write_tests write_tests.cc)
