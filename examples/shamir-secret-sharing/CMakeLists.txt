cmake_minimum_required (VERSION 3.10)

include_directories("include")

file(GLOB srcs "src/*.cpp")
add_executable(sss "test.cpp" ${srcs})
target_link_libraries(sss PRIVATE crypto12381)