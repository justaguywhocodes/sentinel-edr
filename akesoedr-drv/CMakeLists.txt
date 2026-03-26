# akesoedr-drv: Kernel-mode WDM minifilter driver
cmake_minimum_required(VERSION 3.20)

# Target Windows 10+ (WINVER 0x0A00)
set(WDK_WINVER "0x0A00" CACHE STRING "" FORCE)

wdk_add_driver(akesoedr-drv
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
    wfp_callout.c
    self_protect.c
)

target_include_directories(akesoedr-drv PRIVATE ${CMAKE_SOURCE_DIR}/common)

# Link FltMgr.lib for minifilter API, CNG.lib for kernel BCrypt (SHA-256),
# and fwpkclnt.lib for WFP callout registration (FwpsCalloutRegister, FwpmEngineOpen, etc.)
target_link_libraries(akesoedr-drv WDK::FLTMGR WDK::CNG WDK::FWPKCLNT)

# INTEGRITYCHECK is REQUIRED for PsSetCreateProcessNotifyRoutineEx.
# Without this flag, the call returns STATUS_ACCESS_DENIED (0xC0000022).
# Must use APPEND_STRING to LINK_FLAGS since FindWdk uses that property.
set_property(TARGET akesoedr-drv APPEND_STRING PROPERTY LINK_FLAGS " /INTEGRITYCHECK")

message(STATUS "akesoedr-drv: Configured (kernel minifilter driver)")
