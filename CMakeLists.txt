cmake_minimum_required(VERSION 3.16)
project(
  pcapng_slicer
  VERSION 0.0.1
  DESCRIPTION "Library for parsing pcapng files"
  LANGUAGES CXX)

include(cmake/utils.cmake)
include(GNUInstallDirs)
include(GenerateExportHeader)
include(CMakePackageConfigHelpers)

string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}"
               is_top_level)

# Library build options.
option(PCAPNG_SLICER_INSTALL "Generate target for installing pcapng_slicer"
       ${is_top_level})
set_if_undefined(
  PCAPNG_SLICER_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/pcapng_slicer"
  CACHE STRING "Install path for pcapng_slicer package-related CMake files")
if(DEFINED PCAPNG_SLICER_SHARED_LIBS)
  set(BUILD_SHARED_LIBS ${PCAPNG_SLICER_SHARED_LIBS})
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Disable exporting all by default.
set_if_undefined(CMAKE_CXX_VISIBILITY_PRESET hidden)
set_if_undefined(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

add_library(${PROJECT_NAME})
if(BUILD_SHARED_LIBS)
  message(STATUS "Setting up SHARED version of ${PROJECT_NAME}")
else()
  message(STATUS "Setting up STATIC version of ${PROJECT_NAME}")
  target_compile_definitions(${PROJECT_NAME}
                             PUBLIC "PCAPNG_SLICER_STATIC_DEFINE")
endif()

set_target_properties(
  ${PROJECT_NAME} PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR}
                             VERSION ${PROJECT_VERSION})

# Generate export header.
set(export_file_name "export_shared.h")
if(NOT BUILD_SHARED_LIBS)
  set(export_file_name "export_static.h")
endif()
generate_export_header(${PROJECT_NAME} EXPORT_FILE_NAME
                       include/pcapng_slicer/${export_file_name})

target_include_directories(
  ${PROJECT_NAME}
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_subdirectory(include)
add_subdirectory(src)

# Installation.
if(PCAPNG_SLICER_INSTALL AND NOT CMAKE_SKIP_INSTALL_RULES)
  configure_package_config_file(
    cmake/pcapng_slicer-config.cmake.in pcapng_slicer-config.cmake
    INSTALL_DESTINATION "${PCAPNG_SLICER_INSTALL_CMAKEDIR}")

  write_basic_package_version_file(pcapng_slicer-config-version.cmake
                                   COMPATIBILITY SameMajorVersion)

  install(
    TARGETS pcapng_slicer
    EXPORT pcapng_slicer_export
    RUNTIME COMPONENT pcapng_slicer
    LIBRARY COMPONENT pcapng_slicer NAMELINK_COMPONENT pcapng_slicer-dev
    ARCHIVE COMPONENT pcapng_slicer-dev
    INCLUDES
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
  install(
    DIRECTORY include/pcapng_slicer
    COMPONENT pcapng_slicer-dev
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
  install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/include/pcapng_slicer/${export_file_name}
    COMPONENT pcapng_slicer-dev
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/pcapng_slicer)

  set(targets_file "pcapng_slicer-shared-targets.cmake")
  if(NOT BUILD_SHARED_LIBS)
    set(targets_file "pcapng_slicer-static-targets.cmake")
  endif()

  install(
    EXPORT pcapng_slicer_export
    COMPONENT pcapng_slicer-dev
    FILE "${targets_file}"
    DESTINATION "${PCAPNG_SLICER_INSTALL_CMAKEDIR}")

  install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/pcapng_slicer-config.cmake
          ${CMAKE_CURRENT_BINARY_DIR}/pcapng_slicer-config-version.cmake
    COMPONENT pcapng_slicer-dev
    DESTINATION "${PCAPNG_SLICER_INSTALL_CMAKEDIR}")

  if(MSVC)
    set(pdb_file "")
    set(pdb_file_destination "")

    if(BUILD_SHARED_LIBS)
      set(pdb_file "$<TARGET_PDB_FILE:pcapng_slicer>")
      set(pdb_file_destination "${CMAKE_INSTALL_BINDIR}")
    else()
      # TARGET_PDB_FILE does not work for pdb file generated for static library
      # build, determining it manually
      set(pdb_file
          "$<TARGET_FILE_DIR:pcapng_slicer>/$<TARGET_FILE_PREFIX:pcapng_slicer>$<TARGET_FILE_BASE_NAME:pcapng_slicer>.pdb"
      )
      set(pdb_file_destination "${CMAKE_INSTALL_LIBDIR}")
    endif()

    install(
      FILES "${pdb_file}"
      COMPONENT pcapng_slicer-dev
      CONFIGURATIONS Debug RelWithDebInfo
      DESTINATION "${pdb_file_destination}"
      OPTIONAL)
  endif()
endif()
