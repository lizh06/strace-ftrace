
cmake_minimum_required(VERSION 2.6)

project(strace)

set(CMAKE_CXX_FLAGS "-Wall -std=c++0x")
set(EXECUTABLE_OUTPUT_PATH bin)

include_directories(
    inc
)

set(SRCS
    src/main.cpp
    src/Options.cpp
    src/Tracer.cpp
)

add_executable(strace
    ${SRCS}
)


