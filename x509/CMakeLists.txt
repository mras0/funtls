project(x509)

include_directories(${funtls_SOURCE_DIR})

set(_x509_files x509.cpp x509_rsa.cpp x509_ec.cpp x509_io.cpp trust_store.cpp)
if (WIN32)
    set(_x509_files ${_x509_files} trust_store_win32.cpp)
endif()

add_library(x509 STATIC ${_x509_files})
target_link_libraries(x509 util asn1 hash ec int_util)

add_executable(x509_test x509_test.cpp)
target_link_libraries(x509_test util x509)

add_executable(x509_util x509_util.cpp)
target_link_libraries(x509_util util x509)

add_test(x509_test x509_test)
