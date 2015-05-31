project(chacha)

include_directories(${funtls_SOURCE_DIR})

add_library(chacha STATIC chacha.cpp)
target_link_libraries(chacha util)

add_executable(chacha_test chacha_test.cpp)
target_link_libraries(chacha_test util)
add_test(chacha_test chacha_test)
