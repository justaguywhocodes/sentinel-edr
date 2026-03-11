# sentinel-hook: User-mode hooking DLL (C17)
cmake_minimum_required(VERSION 3.20)

add_library(sentinel-hook SHARED
    main.c
    hook_engine.c
    hooks_common.c
    hooks_memory.c
    hooks_thread.c
    hooks_section.c
    hooks_process.c
    pipe_client.c
)

target_include_directories(sentinel-hook PRIVATE ${CMAKE_SOURCE_DIR}/common)
# ole32.lib REMOVED — CoCreateGuid is now dynamically resolved at runtime.
# Static import of ole32.dll causes STATUS_DLL_INIT_FAILED (0xC0000142)
# during early KAPC injection because ole32's DllMain cannot initialize
# before the process COM infrastructure is ready.
target_link_libraries(sentinel-hook PRIVATE advapi32.lib)

# Prevent MSVC default libs from pulling in user32.dll (wsprintfA was
# replaced with _snprintf_s). user32's DllMain also cannot initialize
# during early KAPC injection.
target_link_options(sentinel-hook PRIVATE /NODEFAULTLIB:user32.lib)
set_target_properties(sentinel-hook PROPERTIES
    C_STANDARD 17
    OUTPUT_NAME "sentinel-hook"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

message(STATUS "sentinel-hook: Configured (hooking DLL with hook engine)")
