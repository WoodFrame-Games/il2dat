cmake_minimum_required(VERSION 3.20)
project(HypperDump CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(UNICORN_DIR ${CMAKE_SOURCE_DIR}/third_party/unicorn)

find_package(ZLIB REQUIRED)

add_executable(hypperdump
  src/main.cpp
  src/elf.cpp
  src/emulator.cpp
  src/metadata.cpp
  src/codereg.cpp
  src/zip.cpp
)

target_include_directories(hypperdump PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${UNICORN_DIR}/include
)

# Unicorn is consumed as a DLL (MinGW ld resolves the imports directly).
target_link_libraries(hypperdump PRIVATE "${UNICORN_DIR}/unicorn.dll" ZLIB::ZLIB)

if(MINGW)
  target_link_options(hypperdump PRIVATE -static -static-libgcc -static-libstdc++)
endif()

add_custom_command(TARGET hypperdump POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${UNICORN_DIR}/unicorn.dll" "$<TARGET_FILE_DIR:hypperdump>/unicorn.dll")