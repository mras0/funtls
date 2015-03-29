project(asn1)

include_directories(${hash_SOURCE_DIR})
add_executable(asn1_test asn1_test.cpp)
target_link_libraries(asn1_test hash)
