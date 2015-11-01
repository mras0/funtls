project(util)

include_directories(${util_SOURCE_DIR})
add_library(util STATIC test.cpp base_conversion.cpp buffer.cpp random.cpp ostream_adapter.cpp)

add_executable(util_test util_test.cpp)
target_link_libraries(util_test util)

add_test(util_test util_test)
