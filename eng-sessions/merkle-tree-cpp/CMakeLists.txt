cmake_minimum_required(VERSION 3.26)

project(merkle_test LANGUAGES C CXX)



set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)## Always include the current directory
# Ensure that libc++ is used as the C++ standard library
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

find_package(OpenSSL 3.1 REQUIRED)
if (OPENSSL_FOUND)
    message(STATUS, "OPENSSL Version -> ${OPENSSL_VERSION}")
    message(STATUS, "OPENSSL INC DiR -> ${OPENSSL_INCLUDE_DIR}")
    message(STATUS, "OPENSSL LIBRARY -> ${OPENSSL_LIBRARIES}")
endif()


add_executable(merkle_test ${CMAKE_CURRENT_SOURCE_DIR}/src/sha256.cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)
target_link_libraries(merkle_test PRIVATE OpenSSL::Crypto)