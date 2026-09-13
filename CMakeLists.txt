cmake_minimum_required(VERSION 3.20)

project(PostQuantumSecureCloud)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OPENSSL 3.5 REQUIRED COMPONENTS Algos)

add_executable(
    pqc_cloud
    src/main.cpp
    src/algos/MLKEM.cpp
)

target_link_libraries(
    pqc_cloud
    OpenSSL::Crypto
)