project(tls)

include_directories(${funtls_SOURCE_DIR})

add_library(tls STATIC tls.cpp tls_ciphers.cpp)
target_link_libraries(tls util x509 hash aes rc4 3des)

add_executable(tls_test tls_test.cpp)
target_link_libraries(tls_test tls)

add_test(tls_test tls_test)
