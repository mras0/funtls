project(3des)

include_directories(${funtls_SOURCE_DIR})

add_library(3des STATIC 3des.cpp 3des.h)

add_executable(3des_test 3des_test.cpp)
target_link_libraries(3des_test util 3des)

add_test(3des_test 3des_test)
