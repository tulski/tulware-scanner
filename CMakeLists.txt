cmake_minimum_required(VERSION 3.21)
project(tulware-scanner C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_CLANG_TIDY clang-tidy -checks=-*,readability-*,--warnings-as-errors=*)

set (SRC_LIST main.c)

add_executable(${PROJECT_NAME} ${SRC_LIST})

find_package(OpenSSL REQUIRED)
target_link_libraries(tulware-scanner OpenSSL::SSL)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/malware.data ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)