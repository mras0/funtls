project(bigint)

include_directories(${funtls_SOURCE_DIR})

add_library(bigint STATIC bigint.cpp)

add_executable(bigint_test bigint_test.cpp)
target_link_libraries(bigint_test util bigint)

add_test(bigint_test bigint_test)
