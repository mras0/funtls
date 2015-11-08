project(x509)

include_directories(${funtls_SOURCE_DIR})

set(_x509_files
    x509.cpp
    x509.h
    x509_rsa.cpp
    x509_rsa.h
    x509_ec.cpp
    x509_ec.h
    x509_io.cpp
    x509_io.h
    trust_store.cpp
    trust_store.h
    )
if (WIN32)
    set(_x509_files ${_x509_files} trust_store_win32.cpp trust_store_win32.h)
endif()

add_library(x509 STATIC ${_x509_files})
target_link_libraries(x509 util asn1 hash ec int_util)

add_executable(x509_test x509_test.cpp)
target_link_libraries(x509_test util x509)

add_test(x509_test x509_test)

add_executable(x509_util x509_util.cpp)
target_link_libraries(x509_util util x509)

add_test(x509_util_usage x509_util)
set_tests_properties(x509_util_usage PROPERTIES PASS_REGULAR_EXPRESSION "Usage:")

add_test(x509_util_show x509_util show ${CMAKE_CURRENT_SOURCE_DIR}/localhost_test_cert.crt)
set_tests_properties(x509_util_show PROPERTIES PASS_REGULAR_EXPRESSION "Serial number: 0x00DD43B1B0CCC9E27D.*Issuer: CN=localhost.*Subject: CN=localhost.*Verifying self-signed certificate...OK")