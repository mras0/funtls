project(x509)

include_directories(${funtls_SOURCE_DIR})

add_library(x509 STATIC x509.cpp x509_rsa.cpp x509_io.cpp)
target_link_libraries(x509 util asn1 hash)

add_executable(x509_test x509_test.cpp)
target_link_libraries(x509_test util x509)

add_test(x509_test x509_test)
