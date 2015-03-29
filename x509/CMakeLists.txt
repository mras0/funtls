project(x509)

include_directories(${funtls_SOURCE_DIR})

add_executable(x509_test x509_test.cpp)
target_link_libraries(x509_test util hash asn1)

# HAX
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/server.crt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
add_test(x509_test x509_test)
