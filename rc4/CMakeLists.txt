project(rc4)

include_directories(${funtls_SOURCE_DIR})

add_library(rc4 STATIC rc4.cpp)

add_executable(rc4_test rc4_test.cpp)
target_link_libraries(rc4_test util rc4)

add_test(rc4_test rc4_test)
