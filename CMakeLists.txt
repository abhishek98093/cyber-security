cmake_minimum_required(VERSION 3.10)
project(SecureChatApp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Enable Qt's automatic MOC, UIC, and RCC
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Try Qt5 first, fall back to Qt6
find_package(Qt5 COMPONENTS Widgets Network QUIET)
if (Qt5_FOUND)
    set(Qt_LIBS Qt5::Widgets Qt5::Network)
else()
    find_package(Qt6 COMPONENTS Widgets Network REQUIRED)
    set(Qt_LIBS Qt6::Widgets Qt6::Network)
endif()

find_package(Threads REQUIRED)

find_library(CRYPTOPP_LIB NAMES cryptopp libcryptopp)
if (NOT CRYPTOPP_LIB)
    message(FATAL_ERROR "Crypto++ library not found. Install libcrypto++-dev.")
endif()

find_path(NLOHMANN_JSON_HEADER nlohmann/json.hpp)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

add_executable(SecureChatApp
    src/main.cpp
    src/ChatWindow.cpp
    src/CryptoUtils.cpp
)

target_link_libraries(SecureChatApp PRIVATE ${Qt_LIBS} ${CRYPTOPP_LIB} Threads::Threads)