# akesoedr-agent: User-mode service (C++20)
cmake_minimum_required(VERSION 3.20)

add_executable(akesoedr-agent
    main.cpp
    service.cpp
    config.cpp
    pipeline.cpp
    event_processor.cpp
    process_table.cpp
    network_table.cpp
    json_writer.cpp
    rules/rule_engine.cpp
    rules/rule_parser.cpp
    rules/rule_validator.cpp
    rules/sequence_engine.cpp
    rules/threshold_engine.cpp
    etw/etw_consumer.cpp
    etw/provider_dotnet.cpp
    etw/provider_dns.cpp
    etw/provider_powershell.cpp
    etw/provider_kerberos.cpp
    etw/provider_amsi.cpp
    etw/provider_rpc.cpp
    etw/provider_kernelprocess.cpp
    amsi/amsi_register.cpp
    amsi/amsi_integrity.cpp
    crossvalidation.cpp
    scanner/yara_scanner.cpp
    scanner/onaccess_scanner.cpp
    scanner/memory_scanner.cpp
    output/siem_serializer.cpp
    output/siem_writer.cpp
    cmd_handler.cpp
)

target_include_directories(akesoedr-agent PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# fltLib.lib — FilterConnectCommunicationPort, FilterGetMessage
# advapi32.lib — Service control manager, token queries, ETW (StartTrace, EnableTraceEx2, etc.)
# ole32.lib — CoCreateGuid (AkesoEDREventInit)
# tdh.lib — Trace Data Helper (ETW event parsing, future use)
# libyara — YARA pattern matching engine (P8-T1)
# winhttp.lib — WinHTTP for SIEM output (P9-T5)
target_link_libraries(akesoedr-agent PRIVATE fltLib.lib advapi32.lib ole32.lib tdh.lib libyara winhttp.lib)

set_target_properties(akesoedr-agent PROPERTIES
    CXX_STANDARD 20
    OUTPUT_NAME "akesoedr-agent"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

message(STATUS "akesoedr-agent: Configured (agent service with pipeline + YARA scanner)")
