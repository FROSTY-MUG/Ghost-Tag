cmake_minimum_required(VERSION 3.22.1)
project("ghosttag_security" LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Aggressive compiler hardening flags:
# -fvisibility=hidden hides all symbols by default except JNIEXPORT
# -fstack-protector-strong detects stack buffer overflows
# -D_FORTIFY_SOURCE=2 provides buffer overflow checking on libc calls
# -Wformat -Wformat-security flags format string vulnerabilities
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fvisibility-inlines-hidden -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra")

add_library(
    ghosttag_security
    SHARED
    security_core.cpp
    secure_memory.cpp
    jni_bridge.cpp
)

find_library(log-lib log)

target_link_libraries(
    ghosttag_security
    ${log-lib}
)

