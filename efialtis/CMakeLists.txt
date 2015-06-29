cmake_minimum_required(VERSION 3.2)
project(efialtis)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

set(Efialtis_VERSION_MAJOR 0)
set(Efialtis_VERSION_MINOR 1)

configure_file (
  "${PROJECT_SOURCE_DIR}/config.h.in"
  "${PROJECT_BINARY_DIR}/config.h"
  )

include_directories("${PROJECT_BINARY_DIR}")

set(SOURCE_FILES
    commands.c
    commands.h
    main.c
    main.h
    config.h)

add_executable(efialtis ${SOURCE_FILES})