# akesoedr-watchdog: Lightweight agent monitoring service
cmake_minimum_required(VERSION 3.20)

add_executable(akesoedr-watchdog main.cpp)

target_include_directories(akesoedr-watchdog PRIVATE ${CMAKE_SOURCE_DIR}/common)
target_link_libraries(akesoedr-watchdog PRIVATE advapi32)

set_target_properties(akesoedr-watchdog PROPERTIES
    CXX_STANDARD 20
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

message(STATUS "akesoedr-watchdog: Configured (agent watchdog service)")
