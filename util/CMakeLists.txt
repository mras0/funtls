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

if (MSVC AND ${CMAKE_CXX_COMPILER_VERSION} VERSION_EQUAL 19.0.23506.0)
    set_source_files_properties(util_test.cpp PROPERTIES COMPILE_FLAGS "/wd4702") # warning C4702: unreachable code
endif()

add_test(util_test util_test)
