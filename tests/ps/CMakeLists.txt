cmake_minimum_required (VERSION 3.10)

project(PS)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_EXE_LINKER_FLAGS "-static")

include_directories("include")

file(GLOB srcs "src/*.cpp")
add_executable(ps "test.cpp" ${srcs})
target_link_libraries(ps PRIVATE crypto12381)