project(efialtis C)

set(Efialtis_VERSION_MAJOR 0)
set(Efialtis_VERSION_MINOR 1)
set(CUSTOM_EXTERNAL_HEADERS "${CMAKE_SOURCE_DIR}/shared/c/headers")
set(CUSTOM_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/headers")

configure_file (
  "${CMAKE_CURRENT_SOURCE_DIR}/headers/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/headers/config.h"
  )

include_directories("${CMAKE_CURRENT_BINARY_DIR}/headers")
include_directories("${CUSTOM_HEADERS}")
include_directories("${CUSTOM_EXTERNAL_HEADERS}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

set(SOURCE_FILES
    commands.c
    main.c)

add_executable(efialtis ${SOURCE_FILES} ../shared/c/headers/custom_error.h)
