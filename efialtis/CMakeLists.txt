project(efialtis C)

set(Efialtis_VERSION_MAJOR 0)
set(Efialtis_VERSION_MINOR 1)

configure_file (
  "${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h"
  )
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

include_directories("${CMAKE_CURRENT_BINARY_DIR}")

set(SOURCE_FILES
    commands.c
    commands.h
    main.c
    main.h
    config.h)

add_executable(efialtis ${SOURCE_FILES})
