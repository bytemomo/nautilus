cmake_minimum_required(VERSION 3.20)

project(tls_version_check
  VERSION 1.0.0
  LANGUAGES C
)

option(BUILD_STATIC_RUNTIME "Link the static runtime on MSVC (MT/MTd)" OFF)

find_package(OpenSSL REQUIRED)

add_library(tls_version_check SHARED tls_version_check.c)
target_include_directories(tls_version_check PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(tls_version_check PRIVATE OpenSSL::SSL OpenSSL::Crypto)

set_target_properties(tls_version_check PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  C_STANDARD 11
  C_STANDARD_REQUIRED YES
  OUTPUT_NAME "tls_version_check"
  WINDOWS_EXPORT_ALL_SYMBOLS OFF
)

if(MSVC)
    target_link_libraries(tls_version_check PRIVATE ws2_32)

    if(BUILD_STATIC_RUNTIME)
        foreach(flag_var
      CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
      CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_C_FLAGS_MINSIZEREL)
            if(${flag_var} MATCHES "/MD")
                string(REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
            endif()
            if(${flag_var} MATCHES "/MDd")
                string(REPLACE "/MDd" "/MTd" ${flag_var} "${${flag_var}}")
            endif()
        endforeach()
    endif()

    target_compile_definitions(tls_version_check PRIVATE _CRT_SECURE_NO_WARNINGS=1)
endif()

if(MINGW)
    target_link_libraries(tls_version_check PRIVATE ws2_32)
endif()

message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
