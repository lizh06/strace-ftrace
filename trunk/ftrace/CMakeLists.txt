
cmake_minimum_required(VERSION 2.6)

project(ftrace)

set(CMAKE_CXX_FLAGS "-Wall -std=c++0x -g")
set(EXECUTABLE_OUTPUT_PATH bin)

include_directories(
    inc
)

set(SRCS
    src/main.cpp
    src/Options.cpp
    src/Tracer.cpp
    src/ElfParser.cpp
    src/signals.cpp
)

add_executable(ftrace
    ${SRCS}
)

target_link_libraries(ftrace
    elf
)
