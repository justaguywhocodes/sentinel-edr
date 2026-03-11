# sentinel-agent: User-mode service (C++20)
cmake_minimum_required(VERSION 3.20)

add_executable(sentinel-agent
    main.cpp
    service.cpp
    pipeline.cpp
    event_processor.cpp
    process_table.cpp
    json_writer.cpp
    rules/rule_engine.cpp
    rules/rule_parser.cpp
    rules/sequence_engine.cpp
)

target_include_directories(sentinel-agent PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# fltLib.lib — FilterConnectCommunicationPort, FilterGetMessage
# advapi32.lib — Service control manager, token queries
# ole32.lib — CoCreateGuid (SentinelEventInit)
target_link_libraries(sentinel-agent PRIVATE fltLib.lib advapi32.lib ole32.lib)

set_target_properties(sentinel-agent PROPERTIES
    CXX_STANDARD 20
    OUTPUT_NAME "sentinel-agent"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

message(STATUS "sentinel-agent: Configured (agent service with pipeline)")
