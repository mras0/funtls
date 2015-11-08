project(bigint)

include_directories(${funtls_SOURCE_DIR})

add_library(bigint STATIC bigint.cpp bigint.h)
target_link_libraries(bigint util)

add_executable(bigint_test bigint_test.cpp)
target_link_libraries(bigint_test bigint)
add_test(bigint_test bigint_test)

add_executable(bigint_perf bigint_perf.cpp)
target_link_libraries(bigint_perf bigint)
add_test(bigint_perf bigint_perf)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # Ignore wawnings from boost multiprecision
    set_source_files_properties(bigint_test.cpp bigint_perf.cpp PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter")
endif()
