cmake_minimum_required(VERSION 3.21)
project(tulware-scanner C)

set(CMAKE_C_STANDARD 99)

add_executable(tulware-scanner main.c)
find_package(OpenSSL REQUIRED)
target_link_libraries(tulware-scanner OpenSSL::SSL)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/malware.data ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)