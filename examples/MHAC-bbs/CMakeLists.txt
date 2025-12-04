cmake_minimum_required (VERSION 3.10)

include_directories("include")

file(GLOB srcs "src/*.cpp")
add_executable(mhac_bbs "test.cpp" ${srcs})
target_link_libraries(mhac_bbs PRIVATE crypto12381)