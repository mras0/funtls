project(int_util)

include_directories(${int_util_SOURCE_DIR})
add_library(int_util STATIC int_util.cpp)
target_link_libraries(int_util util)
if (use_bigint)
    target_link_libraries(int_util bigint)
endif()

include_directories(${funtls_SOURCE_DIR})
add_executable(int_util_test int_util_test.cpp)
target_link_libraries(int_util_test int_util)

add_test(int_util_test int_util_test)
