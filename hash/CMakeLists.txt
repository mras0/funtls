project(hash)

include_directories(${hash_SOURCE_DIR})
include_directories(${funtls_SOURCE_DIR})
add_library(hash STATIC hash.cpp sha1.c sha224-256.c sha384-512.c hmac.c usha.c)

add_executable(hash_test hash_test.cpp)
target_link_libraries(hash_test util hash)

add_test(hash_test hash_test)
