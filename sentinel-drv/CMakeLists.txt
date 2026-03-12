# sentinel-drv: Kernel-mode WDM minifilter driver
cmake_minimum_required(VERSION 3.20)

# Target Windows 10+ (WINVER 0x0A00)
set(WDK_WINVER "0x0A00" CACHE STRING "" FORCE)

wdk_add_driver(sentinel-drv
    main.c
    comms.c
    callbacks_process.c
    callbacks_thread.c
    callbacks_object.c
    callbacks_imageload.c
    callbacks_registry.c
    kapc_inject.c
    minifilter.c
    minifilter_pipes.c
    file_hash.c
)

target_include_directories(sentinel-drv PRIVATE ${CMAKE_SOURCE_DIR}/common)

# Link FltMgr.lib for minifilter API and CNG.lib for kernel BCrypt (SHA-256)
target_link_libraries(sentinel-drv WDK::FLTMGR WDK::CNG)

# INTEGRITYCHECK is REQUIRED for PsSetCreateProcessNotifyRoutineEx.
# Without this flag, the call returns STATUS_ACCESS_DENIED (0xC0000022).
# Must use APPEND_STRING to LINK_FLAGS since FindWdk uses that property.
set_property(TARGET sentinel-drv APPEND_STRING PROPERTY LINK_FLAGS " /INTEGRITYCHECK")

message(STATUS "sentinel-drv: Configured (kernel minifilter driver)")
