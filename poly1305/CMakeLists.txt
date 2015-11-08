project(poly1305)

include_directories(${funtls_SOURCE_DIR})

add_library(poly1305 STATIC poly1305.cpp poly1305.h)
target_link_libraries(poly1305 util int_util)

add_executable(poly1305_test poly1305_test.cpp)
target_link_libraries(poly1305_test util int_util)
add_test(poly1305_test poly1305_test)
