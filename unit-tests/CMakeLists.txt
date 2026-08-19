include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.15.3
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(Catch2)

file(GLOB unit_test_srcs CONFIGURE_DEPENDS "*.cpp")
add_executable(crypto12381-tests ${unit_test_srcs})
target_link_libraries(crypto12381-tests PRIVATE crypto12381 Catch2::Catch2WithMain)

if(BUILD_TESTING)
    add_test(NAME crypto12381-tests COMMAND crypto12381-tests)
endif()
