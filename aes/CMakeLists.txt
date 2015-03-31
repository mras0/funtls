project(aes)

include_directories(${funtls_SOURCE_DIR})

add_library(aes STATIC aes.cpp)

add_executable(aes_test aes_test.cpp)
target_link_libraries(aes_test util aes)

add_test(aes_test aes_test)
