cmake_minimum_required(VERSION 3.27)
project(CryptoCompare C)

set(CMAKE_C_STANDARD 11)

include_directories(cryptlib)
link_directories(cryptlib)

add_executable(CryptoCompare main.c)

target_link_libraries(CryptoCompare cl)
