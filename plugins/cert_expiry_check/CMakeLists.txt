cmake_minimum_required(VERSION 3.20)
project(cert_expiry_check LANGUAGES C)

find_package(OpenSSL REQUIRED)

add_library(cert_expiry_check SHARED cert_expiry_check.c)
target_link_libraries(cert_expiry_check PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(cert_expiry_check PRIVATE ws2_32)
endif()
