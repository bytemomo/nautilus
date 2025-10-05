cmake_minimum_required(VERSION 3.16)
project(mqtt_auth_check C)
set(CMAKE_C_STANDARD 11)

add_library(mqtt_auth_check SHARED mqtt_auth_check.c)

set_target_properties(mqtt_auth_check PROPERTIES PREFIX "")
