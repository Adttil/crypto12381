cmake_minimum_required (VERSION 3.10)

include_directories("include")

file(GLOB srcs "src/*.cpp")
add_executable(ac_rps "test.cpp" ${srcs})
target_link_libraries(ac_rps PRIVATE crypto12381)