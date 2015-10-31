project(hash)

include_directories(${funtls_SOURCE_DIR})

add_executable(hash_test hash_test.cpp)
target_link_libraries(hash_test util hash)

add_test(hash_test hash_test)

include_directories(${hash_SOURCE_DIR})
add_library(hash STATIC hash.cpp sha/sha1.c sha/sha224-256.c sha/sha384-512.c sha/hmac.c sha/usha.c md5/md5.c)
if (MSVC)
    # C4245: 'initializing': conversion from '__int64' to 'uint64_t', signed/unsigned mismatch
    set_source_files_properties(sha/sha384-512.c PROPERTIES COMPILE_FLAGS "/wd4245")
endif()
