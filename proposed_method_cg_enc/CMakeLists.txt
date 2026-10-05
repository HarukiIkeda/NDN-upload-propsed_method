cmake_minimum_required(VERSION 3.10)
project(NDN_Upload CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(PkgConfig REQUIRED)
pkg_check_modules(NDN_CXX REQUIRED libndn-cxx)

find_package(OpenSSL REQUIRED)

include_directories(${NDN_CXX_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
link_directories(${NDN_CXX_LIBRARY_DIRS})

add_library(crypto_utils crypto_utils.cpp)
target_link_libraries(crypto_utils ${OPENSSL_LIBRARIES})

add_executable(consumer consumer.cpp)
target_link_libraries(consumer ${NDN_CXX_LIBRARIES} crypto_utils)

add_executable(gateway gateway.cpp)
target_link_libraries(gateway ${NDN_CXX_LIBRARIES} crypto_utils)

add_executable(producer producer.cpp)
target_link_libraries(producer ${NDN_CXX_LIBRARIES} crypto_utils)
