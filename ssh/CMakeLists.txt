project(ssh)

include_directories(${funtls_SOURCE_DIR})

add_library(ssh STATIC ssh.cpp ssh.h)
target_link_libraries(ssh util)

add_executable(ssh_test ssh_test.cpp)
target_link_libraries(ssh_test ssh int_util)
add_test(ssh_test ssh_test)

add_executable(ssh_client ssh_client.cpp)
target_link_libraries(ssh_client ssh x509 aes)

set(OPENSSH_DIR "$ENV{HOME}/build/openssh-6.8p1" CACHE PATH "Path to openssh commands")
configure_file(sshd_config.in ${CMAKE_CURRENT_BINARY_DIR}/sshd_config @ONLY)
configure_file(start_server.sh.in ${CMAKE_CURRENT_BINARY_DIR}/start_server.sh @ONLY)
