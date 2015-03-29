project(asn1)

include_directories(${funtls_SOURCE_DIR})

add_library(asn1 STATIC asn1.cpp)
target_link_libraries(asn1 util)

add_executable(asn1_test asn1_test.cpp)
target_link_libraries(asn1_test util hash asn1)

# HAX
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/server.crt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
add_test(asn1_test asn1_test)
