cmake_minimum_required(VERSION 2.8)
project(funtls)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1) # For YouCompleteMe support (see https://github.com/Valloric/YouCompleteMe)

enable_testing()
# http://stackoverflow.com/questions/16158091/cmake-setting-an-environmental-variable-for-ctest-or-otherwise-getting-failed
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --force-new-ctest-process --output-on-failure)

set(common_flags "-Wall -Wextra -pthread -g3")

set(use_asan  TRUE  CACHE BOOL "Use address sanitizier")
set(use_tsan  FALSE CACHE BOOL "Use thread sanitizier")
set(use_ubsan TRUE  CACHE BOOL "Use undefined behavior sanitizier")

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

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 ${common_flags}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 ${common_flags}")

# Ugly handling of boost stuff
set(boost_dir "${CMAKE_CURRENT_SOURCE_DIR}/../boost_1_57_0/" CACHE PATH "Root of boost installation")
include_directories(${boost_dir})
add_definitions("-DBOOST_ALL_NO_LIB -DBOOST_SYSTEM_NO_DEPRECATED")
add_library(boost STATIC ${boost_dir}/libs/system/src/error_code.cpp)

add_subdirectory(util)
add_subdirectory(ec)
add_subdirectory(3des)
add_subdirectory(rc4)
add_subdirectory(aes)
add_subdirectory(hash)
add_subdirectory(asn1)
add_subdirectory(x509)
add_subdirectory(tls)

include_directories(${funtls_SOURCE_DIR})
add_executable(funtls main.cpp)
target_link_libraries(funtls boost util hash asn1 x509 tls)

find_program(HAS_CTAGS ctags)
if (HAS_CTAGS)
    message("ctags found")

    set_source_files_properties(tags PROPERTIES GENERATED true)
    add_custom_target(tags
        COMMAND ctags -R --c++-kinds=+p --fields=+iaS --extra=+q --exclude=build* .
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_dependencies(funtls tags)
endif()
