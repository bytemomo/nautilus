cmake_minimum_required(VERSION 3.20)
project(telnet_default_creds LANGUAGES C)

add_library(telnet_default_creds SHARED telnet_default_creds.c)

set_target_properties(telnet_default_creds PROPERTIES PREFIX "")
target_include_directories(telnet_default_creds PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../../kraken/pkg/plugabi)

if(WIN32)
    target_link_libraries(telnet_default_creds PRIVATE ws2_32)
endif()
