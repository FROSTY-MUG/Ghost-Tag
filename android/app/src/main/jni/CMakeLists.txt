cmake_minimum_required(VERSION 3.22.1)

# Define the application TurboModule library (New Architecture)
project(appmodules LANGUAGES CXX C)

# Include React Native application setup (builds appmodules.so from OnLoad.cpp + autolinking)
include(${REACT_ANDROID_DIR}/cmake-utils/ReactNative-application.cmake)

# Include ghosttag_security native library module
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../cpp" "${CMAKE_CURRENT_BINARY_DIR}/ghosttag_security_build")
