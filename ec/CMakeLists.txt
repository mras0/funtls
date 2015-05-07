project(ec)

include_directories(${funtls_SOURCE_DIR})

add_library(ec STATIC ec.cpp)

add_executable(ec_test ec_test.cpp)
target_link_libraries(ec_test util ec)

add_test(ec_test ec_test)
