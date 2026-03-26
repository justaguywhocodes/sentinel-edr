cmake_minimum_required(VERSION 3.20)
project(AkesoEDR VERSION 1.0.0 LANGUAGES C CXX)

# ── Global settings ──────────────────────────────────────────────────────────
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Output all binaries to a common location
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ── WDK Detection via FindWdk ────────────────────────────────────────────────
# Uses the FindWdk CMake module (BSD-3, SergiusTheBest/FindWDK).
# Provides wdk_add_driver() for building .sys files with proper WDK flags.

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(Wdk)

if(NOT WDK_FOUND)
    message(STATUS "WDK not found -- kernel-mode components will be skipped")
    message(STATUS "  Install the Windows Driver Kit to enable driver builds")
endif()

# ── Common include path ──────────────────────────────────────────────────────
include_directories(${CMAKE_SOURCE_DIR}/common)

# ── Dependencies ─────────────────────────────────────────────────────────────

# libyara — YARA pattern matching engine (built from source)
add_subdirectory(deps/yara)

# ── Sub-projects ─────────────────────────────────────────────────────────────

# Kernel-mode driver (requires WDK)
if(WDK_FOUND)
    add_subdirectory(akesoedr-drv)
else()
    message(STATUS "Skipping akesoedr-drv (no WDK)")
endif()

# User-mode components (always built)
add_subdirectory(akesoedr-hook)
add_subdirectory(akesoedr-agent)
add_subdirectory(akesoedr-cli)
add_subdirectory(akesoedr-amsi)
add_subdirectory(akesoedr-watchdog)

# Tests
enable_testing()
add_subdirectory(tests)
