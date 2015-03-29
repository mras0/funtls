project(x509)

include_directories(${funtls_SOURCE_DIR})

add_library(x509 STATIC x509.cpp)
target_link_libraries(x509 util asn1)

add_executable(x509_test x509_test.cpp)
target_link_libraries(x509_test util hash asn1 x509)

# HAX
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/server.crt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
add_test(x509_test x509_test)
