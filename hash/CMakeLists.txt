project(hash)

include_directories(${hash_SOURCE_DIR})
include_directories(hash)
add_library(hash STATIC sha1.c sha224-256.c)

add_executable(hash_test hash_test.cpp)
target_link_libraries(hash_test hash)
