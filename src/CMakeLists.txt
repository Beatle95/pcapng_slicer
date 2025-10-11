target_sources(
  ${PROJECT_NAME}
  PRIVATE reader.cc
          block_reader.h
          block_reader.cc
          packet_private.h
          packet_private.cc
          block_types.h
          section_private.h
          section_private.cc
          packet.cc
          options.cc
          interface.cc
          interface_private.h)
