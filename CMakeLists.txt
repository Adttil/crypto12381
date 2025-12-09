cmake_minimum_required (VERSION 3.10)

project(CRYPTO12381)

option(CRYPTO12381_INCLUDE_EXAMPLES "build examples" ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_EXE_LINKER_FLAGS "-static")

file(GLOB crypto12381_srcs "src/*.cpp")
file(GLOB miracl_core_srcs "3rd-party/miracl-core/*.cpp")
add_library(crypto12381 STATIC ${crypto12381_srcs} ${miracl_core_srcs})
target_include_directories(crypto12381 PUBLIC "include" PRIVATE "3rd-party")

add_executable(example_ps "example_ps.cpp")
target_link_libraries(example_ps PRIVATE crypto12381)

add_executable(test "test.cpp")
target_link_libraries(test PRIVATE crypto12381)

add_executable(algebra_test "algebra_test.cpp")
target_link_libraries(algebra_test PRIVATE crypto12381)

if(CRYPTO12381_INCLUDE_EXAMPLES)
    add_subdirectory(examples)
endif()