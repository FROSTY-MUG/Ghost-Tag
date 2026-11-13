/**
 * @file security_core.cpp
 * @summary Native Anti-Debugging, Anti-Hooking, and Anti-Tamper Implementation.
 */

#include "security_core.h"

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/system_properties.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

namespace ghosttag {

// Common root paths searched on Android
static const char* const SU_PATHS[] = {
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/system/su",
    "/system/bin/failsafe/su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/data/local/su",
    "/system/sd/xbin/su",
    "/system/bin/.ext/.su",
    "/system/usr/we-need-root/su-backup",
    "/data/adb/magisk",
    "/data/adb/ksu",
    "/system/app/Superuser.apk",
    nullptr
};

// Known dynamic instrumentation libraries searched in memory maps
static const char* const HOOK_SIGNATURES[] = {
    "frida-agent",
    "frida-gadget",
    "libfrida",
    "gum-js-loop",
    "gmain",
    "libxposed",
    "XposedBridge",
    "edxposed",
    "sandhook",
    "libsubstrate",
    "cydiasubstrate",
    nullptr
};

IntegrityReport SecurityCore::checkIntegrity() {
    IntegrityReport report;
    report.is_debugger_active = false;
    report.is_hooked = false;
    report.is_rooted = false;
    report.is_emulator = false;
    report.is_signature_valid = true;

    // 1. Check for attached debuggers
    if (checkPtrace()) {
        report.is_debugger_active = true;
        report.indicators.push_back("PTRACE_ATTACH_DETECTED");
    }
    if (checkTracerPid()) {
        report.is_debugger_active = true;
        report.indicators.push_back("TRACER_PID_ACTIVE");
    }
    if (checkWchan()) {
        report.is_debugger_active = true;
        report.indicators.push_back("SYS_PTRACE_WCHAN");
    }

    // 2. Check for dynamic instrumentation / hooking
    if (checkProcMaps(report.indicators)) {
        report.is_hooked = true;
    }
    if (checkFridaPort()) {
        report.is_hooked = true;
        report.indicators.push_back("FRIDA_DEFAULT_PORT_OPEN");
    }

    // 3. Check for root escalation
    if (checkSuBinaries(report.indicators)) {
        report.is_rooted = true;
    }
    if (checkBuildProperties(report.indicators)) {
        report.is_rooted = true;
    }

    // 4. Check for emulator indicators
    if (isEmulatorDetected()) {
        report.is_emulator = true;
        report.indicators.push_back("EMULATOR_ENVIRONMENT");
    }

    report.is_secure = !report.is_debugger_active &&
                       !report.is_hooked &&
                       !report.is_rooted &&
                       report.is_signature_valid;

    return report;
}

bool SecurityCore::isDebuggerAttached() {
    return checkPtrace() || checkTracerPid() || checkWchan();
}

bool SecurityCore::isHookingDetected() {
    std::vector<std::string> dummy;
    return checkProcMaps(dummy) || checkFridaPort();
}

bool SecurityCore::isRootDetected() {
    std::vector<std::string> dummy;
    return checkSuBinaries(dummy) || checkBuildProperties(dummy);
}

bool SecurityCore::checkPtrace() {
    // Attempt ptrace attach to self. If already traced by GDB/LLDB, this returns -1.
    long ret = ptrace(PTRACE_TRACEME, 0, 1, 0);
    if (ret < 0) {
        return true; // Debugger already attached!
    }
    return false;
}

bool SecurityCore::checkTracerPid() {
    std::ifstream statusFile("/proc/self/status");
    if (!statusFile.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(statusFile, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            int pid = 0;
            if (sscanf(line.c_str(), "TracerPid:\t%d", &pid) == 1) {
                if (pid > 0) {
                    return true;
                }
            }
            break;
        }
    }
    return false;
}

bool SecurityCore::checkWchan() {
    std::ifstream wchanFile("/proc/self/wchan");
    if (!wchanFile.is_open()) {
        return false;
    }

    std::string content;
    std::getline(wchanFile, content);
    if (content.find("sys_ptrace") != std::string::npos ||
        content.find("ptrace_stop") != std::string::npos) {
        return true;
    }
    return false;
}

bool SecurityCore::checkProcMaps(std::vector<std::string>& found_indicators) {
    std::ifstream mapsFile("/proc/self/maps");
    if (!mapsFile.is_open()) {
        return false;
    }

    bool detected = false;
    std::string line;
    while (std::getline(mapsFile, line)) {
        for (int i = 0; HOOK_SIGNATURES[i] != nullptr; ++i) {
            if (line.find(HOOK_SIGNATURES[i]) != std::string::npos) {
                detected = true;
                found_indicators.push_back(std::string("HOOK_LIB_") + HOOK_SIGNATURES[i]);
                break;
            }
        }
    }
    return detected;
}

bool SecurityCore::checkFridaPort() {
    // Attempt non-blocking connection to 127.0.0.1:27042 (Frida server default)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(27042);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }

    int res = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    close(sock);

    return (res == 0);
}

bool SecurityCore::checkSuBinaries(std::vector<std::string>& found_indicators) {
    bool found = false;
    for (int i = 0; SU_PATHS[i] != nullptr; ++i) {
        if (access(SU_PATHS[i], F_OK) == 0) {
            found = true;
            found_indicators.push_back(std::string("SU_BINARY_") + SU_PATHS[i]);
        }
    }
    return found;
}

bool SecurityCore::checkBuildProperties(std::vector<std::string>& found_indicators) {
    bool compromised = false;
    char prop_val[PROP_VALUE_MAX] = {0};

    if (__system_property_get("ro.debuggable", prop_val) > 0) {
        if (strcmp(prop_val, "1") == 0) {
            compromised = true;
            found_indicators.push_back("PROP_RO_DEBUGGABLE_1");
        }
    }

    if (__system_property_get("ro.secure", prop_val) > 0) {
        if (strcmp(prop_val, "0") == 0) {
            compromised = true;
            found_indicators.push_back("PROP_RO_SECURE_0");
        }
    }

    return compromised;
}

bool SecurityCore::isEmulatorDetected() {
    char prop_val[PROP_VALUE_MAX] = {0};

    if (__system_property_get("ro.hardware", prop_val) > 0) {
        if (strstr(prop_val, "goldfish") != nullptr || strstr(prop_val, "ranchu") != nullptr) {
            return true;
        }
    }

    if (__system_property_get("ro.kernel.qemu", prop_val) > 0) {
        if (strcmp(prop_val, "1") == 0) {
            return true;
        }
    }

    return false;
}

} // namespace ghosttag
