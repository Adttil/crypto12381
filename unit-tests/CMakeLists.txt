include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.15.3
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(Catch2)

add_executable(
    crypto12381-tests
    "algebra.cpp"
    "chunk_range.cpp"
    "constant.cpp"
    "crypto12381.cpp"
    "data_access.cpp"
    "g1_point.cpp"
    "g2_point.cpp"
    "general.cpp"
    "interface.cpp"
    "liner_pair.cpp"
    "miracl_core_interface.cpp"
    "random.cpp"
    "set.cpp"
    "zp_number.cpp"
)
target_link_libraries(crypto12381-tests PRIVATE crypto12381 Catch2::Catch2WithMain)

add_test(NAME crypto12381-tests COMMAND crypto12381-tests)
