project(tls)

include_directories(${funtls_SOURCE_DIR})

add_library(tls STATIC
    tls.cpp
    tls.h
    tls_base.cpp
    tls_base.h
    tls_ciphers.cpp
    tls_ciphers.h
    tls_client.cpp
    tls_client.h
    tls_ecc.cpp
    tls_ecc.h
    tls_kex.cpp
    tls_kex.h
    tls_ser.h
    )
target_link_libraries(tls util x509 hash aes rc4 3des ec chacha poly1305 int_util)

add_executable(tls_test tls_test.cpp)
target_link_libraries(tls_test tls)

add_test(tls_test tls_test)
