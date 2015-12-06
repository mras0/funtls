cmake_minimum_required(VERSION 2.8)
project(funtls)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1) # For YouCompleteMe support (see https://github.com/Valloric/YouCompleteMe)

enable_testing()

if (MSVC)
    set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "Supported build configurations" FORCE)

    # Reset flags
    set(CMAKE_CXX_FLAGS "/EHsc")
    set(CMAKE_CXX_FLAGS_DEBUG "/MTd /Od /D_DEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "/MT /O2 /DNDEBUG")

    # Always include debug information
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Zi /Zo")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /DEBUG")

    add_definitions("/W4")
    add_definitions("/wd4127") # C4127: conditional expression is constant

    # MSVC++ 2015 RTM       19.0.23026
    # MSVC++ 2015 Update 1  19.0.23506
    if (${CMAKE_CXX_COMPILER_VERSION} VERSION_EQUAL 19.0.23506.0)
        add_definitions("/wd4592") # C4592: '???': symbol will be dynamically initialized (implementation limitation)
    endif()

    add_definitions("-DWIN32")
    add_definitions("-D__PRETTY_FUNCTION__=__func__")
    add_definitions("-D_SCL_SECURE_NO_WARNINGS")
    add_definitions("-DUNICODE -D_UNICODE")
else()
    set(use_asan   TRUE  CACHE BOOL "Use address sanitizier")
    set(use_tsan   FALSE CACHE BOOL "Use thread sanitizier")
    set(use_ubsan  TRUE  CACHE BOOL "Use undefined behavior sanitizier")

    set(common_flags "-Wall -Wextra -pthread -g -fno-omit-frame-pointer")
    if (use_asan)
        message("Using address sanitizer")
        set(common_flags "${common_flags} -fsanitize=address")
    endif()
    if (use_tsan)
        message("Using thread sanitizer")
        set(common_flags "${common_flags} -fsanitize=thread")
    endif()
    if (use_ubsan)
        message("Using undefined behavior sanitizer")
        set(common_flags "${common_flags} -fsanitize=undefined")
    endif()

    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 4.9)
            set(common_flags "${common_flags} -Wno-deprecated-declarations")
        endif()
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
            set(common_flags "${common_flags} -Wno-unused-local-typedef")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lc++abi")
    else()
        message(WARNING "Unknown compiler ${CMAKE_CXX_COMPILER_ID}")
    endif()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 ${common_flags}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 ${common_flags}")
endif()

set(use_bigint TRUE CACHE BOOL "Use funtls bigint implmentation")
if (use_bigint)
    message("Using funtls bigint")
    add_definitions("-DUSE_FUNTLS_BIGINT")
endif()

# http://stackoverflow.com/questions/16158091/cmake-setting-an-environmental-variable-for-ctest-or-otherwise-getting-failed
if (CMAKE_CONFIGURATION_TYPES)
    add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --force-new-ctest-process --output-on-failure --build-config "$<CONFIGURATION>")
else()
    add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --force-new-ctest-process --output-on-failure)
endif()

# Creating a test where the output is piped is a pain in the ... with CMake
# http://cmake.3232098.n2.nabble.com/testing-with-standard-output-td3256689.html
function(add_piped_test name cmd1 cmd1_args cmd2 cmd2_args)
    add_test(NAME ${name} COMMAND
        ${CMAKE_COMMAND}
        -DCMD1=${cmd1}
        -DCMD1_ARGS:STRING=${cmd1_args}
        -DCMD2=${cmd2}
        -DCMD2_ARGS:STRING=${cmd2_args}
        -P ${funtls_SOURCE_DIR}/ctest_pipe.cmake
     )
endfunction()


# Ugly handling of boost stuff
set(boost_dir "${CMAKE_CURRENT_SOURCE_DIR}/../boost_1_59_0/" CACHE PATH "Root of boost installation")
include_directories(${boost_dir})
add_definitions("-DBOOST_ALL_NO_LIB -DBOOST_SYSTEM_NO_DEPRECATED -DBOOST_ERROR_CODE_HEADER_ONLY")
if (WIN32)
    add_definitions("-D_WIN32_WINNT=0x0501")
endif()

find_program(OPENSSL_EXE openssl)
if (OPENSSL_EXE)
    message("openssl found ${OPENSSL_EXE}")
endif()

add_subdirectory(util)
add_subdirectory(bigint)
add_subdirectory(int_util)
add_subdirectory(ec)
add_subdirectory(chacha)
add_subdirectory(poly1305)
add_subdirectory(3des)
add_subdirectory(rc4)
add_subdirectory(aes)
add_subdirectory(hash)
add_subdirectory(asn1)
add_subdirectory(x509)
add_subdirectory(tls)
add_subdirectory(ssh)

include_directories(${funtls_SOURCE_DIR})

add_library(https_fetch https_fetch.cpp https_fetch.h)
target_link_libraries(https_fetch tls)

add_executable(funtls client.cpp)
target_link_libraries(funtls https_fetch)

add_library(tcp_tls_server tcp_tls_server.cpp tcp_tls_server.h)
target_link_libraries(tcp_tls_server tls)

add_executable(test_server test_server.cpp)
target_link_libraries(test_server tcp_tls_server)

add_executable(self_test test_server.cpp)
target_link_libraries(self_test https_fetch tcp_tls_server)
set_target_properties(self_test PROPERTIES COMPILE_FLAGS "-DSELF_TEST")
add_test(self_test self_test)

if (OPENSSL_EXE)
    add_executable(test_against_openssl test_server.cpp)
    target_link_libraries(test_against_openssl tcp_tls_server)
    file(TO_NATIVE_PATH "${OPENSSL_EXE}" OPENSSL_EXE_ESCAPED)
    string(REPLACE "\\" "\\\\" OPENSSL_EXE_ESCAPED ${OPENSSL_EXE_ESCAPED})
    set_target_properties(test_against_openssl PROPERTIES COMPILE_FLAGS "-DOPENSSL_TEST -DOPENSSL_EXE=\\\"${OPENSSL_EXE_ESCAPED}\\\"")
    add_test(test_against_openssl test_against_openssl 0 ${OPENSSL_EXE})
    set_tests_properties(test_against_openssl PROPERTIES PASS_REGULAR_EXPRESSION "openssl exited OK")
endif()

if (NOT WIN32)
    find_program(HAS_CTAGS ctags)
    if (HAS_CTAGS)
        message("ctags found")

        set_source_files_properties(tags PROPERTIES GENERATED true)
        add_custom_target(tags
            COMMAND ctags -R --c++-kinds=+p --fields=+iaS --extra=+q --exclude=build* .
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
        add_dependencies(funtls tags)
    endif()
endif()
