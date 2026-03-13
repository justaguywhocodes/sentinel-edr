# sentinel-cli: Console management tool (C++20)
cmake_minimum_required(VERSION 3.20)

add_executable(sentinel-cli
    main.cpp
)

target_include_directories(sentinel-cli PRIVATE ${CMAKE_SOURCE_DIR}/common)
set_target_properties(sentinel-cli PROPERTIES
    CXX_STANDARD 20
    OUTPUT_NAME "sentinel-cli"
)

set_target_properties(sentinel-cli PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

message(STATUS "sentinel-cli: Configured (CLI with command pipe client)")
