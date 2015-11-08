project(util)

include_directories(${util_SOURCE_DIR})
add_library(util STATIC
    async_result.h
    base_conversion.cpp
    base_conversion.h
    buffer.cpp
    buffer.h
    ostream_adapter.cpp
    ostream_adapter.h
    random.cpp
    random.h
    test.cpp
    test.h
    )

add_executable(util_test util_test.cpp)
target_link_libraries(util_test util)

add_test(util_test util_test)
