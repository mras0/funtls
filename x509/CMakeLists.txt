project(x509)

include_directories(${funtls_SOURCE_DIR})

add_library(x509 STATIC x509.cpp x509_rsa.cpp x509_ec.cpp x509_io.cpp)
target_link_libraries(x509 util asn1 hash ec ${bigint_LIBRARIES})

add_executable(x509_test x509_test.cpp)
target_link_libraries(x509_test util x509)

add_executable(x509_util x509_util.cpp)
target_link_libraries(x509_util util x509)

add_test(x509_test x509_test)
