cmake_minimum_required(VERSION 3.21)
project(tulus C)

set(CMAKE_C_STANDARD 99)

add_executable(tulus main.c)
find_package(OpenSSL REQUIRED)
target_link_libraries(tulus OpenSSL::SSL)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/malware.data ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)