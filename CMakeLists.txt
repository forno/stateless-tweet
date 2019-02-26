cmake_minimum_required(VERSION 3.13)
project(stateless_tweet)

set(CMAKE_CXX_STANDARD          17  CACHE STRING "CXX standard version")
set(CMAKE_CXX_STANDARD_REQUIRED ON  CACHE BOOL   "version required")
set(CMAKE_CXX_EXTENSIONS        OFF CACHE BOOL   "compiler extension")

find_package(Boost   REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(stateless-tweet src/main.cpp)
target_link_libraries(stateless-tweet Boost::system OpenSSL::SSL Threads::Threads)
install(TARGETS stateless-tweet)
