project(x509)

include_directories(${funtls_SOURCE_DIR})

add_library(x509 STATIC x509.cpp x509_rsa.cpp)
target_link_libraries(x509 util asn1)

add_executable(x509_test x509_test.cpp)
target_link_libraries(x509_test util hash asn1 x509)

add_test(x509_test x509_test)
