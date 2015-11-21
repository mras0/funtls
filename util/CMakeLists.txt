project(util)

if (WIN32)
    set(platform_dependent win32_util.cpp win32_util.h child_process_win32.cpp)
else()
    set(platform_dependent child_process_posix.cpp)
endif()

include_directories(${util_SOURCE_DIR})
add_library(util STATIC
    async_result.h
    base_conversion.cpp
    base_conversion.h
    buffer.cpp
    buffer.h
    child_process.h
    ${platform_dependent}
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
