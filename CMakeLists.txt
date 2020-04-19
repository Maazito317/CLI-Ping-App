cmake_minimum_required(VERSION 3.13)
project(CLI-Ping-App)
set(CMAKE_C_STANDARD 11)
set(SOURCE_FILES main.c hello.c)


add_executable(CLI-Ping-App ${SOURCE_FILES})