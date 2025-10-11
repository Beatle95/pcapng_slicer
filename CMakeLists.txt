cmake_minimum_required(VERSION 3.16)
project(
  pcapng_slicer
  VERSION 0.0.1
  DESCRIPTION "Library for parsing pcapng files"
  LANGUAGES CXX)

# Library build options.
if(DEFINED PCAPNG_SLICER_SHARED_LIBS)
  set(BUILD_SHARED_LIBS ${PCAPNG_SLICER_SHARED_LIBS})
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(${PROJECT_NAME})

target_include_directories(${PROJECT_NAME}
                           PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME}
                           PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_subdirectory(include/pcapng_slicer)
add_subdirectory(src)
