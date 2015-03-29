cmake_minimum_required(VERSION 2.8)
project(funtls)

set(common_flags "-Wall -Wextra -fsanitize=address -pthread")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 ${common_flags}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 ${common_flags}")

# Ugly handling of boost stuff
set(boost_dir "${CMAKE_CURRENT_SOURCE_DIR}/../../build/boost_1_57_0/" CACHE PATH "Root of boost installation")
include_directories(${boost_dir})
add_definitions("-DBOOST_ALL_NO_LIB -DBOOST_SYSTEM_NO_DEPRECATED")
add_library(boost STATIC ${boost_dir}/libs/system/src/error_code.cpp)

add_subdirectory(hash)
add_subdirectory(asn1)

add_executable(funtls main.cpp tls.cpp variant.cpp)
target_link_libraries(funtls boost)
