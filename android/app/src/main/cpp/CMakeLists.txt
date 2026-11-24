cmake_minimum_required(VERSION 3.22.1)

# Build ghosttag_security native library (hardware-anchored security & anti-tamper checks)
add_library(
    ghosttag_security
    SHARED
    security_core.cpp
    secure_memory.cpp
    jni_bridge.cpp
)

target_include_directories(ghosttag_security PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(ghosttag_security PRIVATE cxx_std_17)
target_compile_options(ghosttag_security PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra)

find_library(log-lib log)
target_link_libraries(
    ghosttag_security
    ${log-lib}
)

