project(ec)

include_directories(${funtls_SOURCE_DIR})

add_library(ec STATIC ec.cpp ec.h)
target_link_libraries(ec int_util)

add_executable(ec_test ec_test.cpp)
target_link_libraries(ec_test util ec)

add_test(ec_test ec_test)
