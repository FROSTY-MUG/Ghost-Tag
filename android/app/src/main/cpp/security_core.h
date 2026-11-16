/**
 * @file security_core.h
 * @summary Ghost-Tag Native Security & Environment Inspection.
 *
 * Ghost-Tag includes optional runtime environment checks, but these do not prevent
 * reverse engineering or protect data on a compromised or unlocked device.
 */

#ifndef GHOSTTAG_SECURITY_CORE_H
#define GHOSTTAG_SECURITY_CORE_H

#include <string>
#include <vector>

namespace ghosttag {

struct IntegrityReport {
    bool is_secure;
    bool is_debugger_active;
    bool is_hooked;
    bool is_rooted;
    bool is_emulator;
    bool is_signature_valid;
    std::vector<std::string> indicators;
};

class SecurityCore {
public:
    /**
     * Executes the comprehensive suite of native integrity checks.
     * @return Complete integrity diagnostic report.
     */
    static IntegrityReport checkIntegrity();

    /**
     * Checks if a debugger is attached via ptrace or TracerPid.
     */
    static bool isDebuggerAttached();

    /**
     * Checks /proc/self/maps and process runtime for hooking agents (Frida, Xposed, Substrate).
     */
    static bool isHookingDetected();

    /**
     * Checks file system and build properties for root escalation binaries.
     */
    static bool isRootDetected();

    /**
     * Checks if running inside an untrusted virtual machine / emulator.
     */
    static bool isEmulatorDetected();

private:
    static bool checkPtrace();
    static bool checkTracerPid();
    static bool checkWchan();
    static bool checkProcMaps(std::vector<std::string>& found_indicators);
    static bool checkFridaPort();
    static bool checkSuBinaries(std::vector<std::string>& found_indicators);
    static bool checkBuildProperties(std::vector<std::string>& found_indicators);
};

} // namespace ghosttag

#endif // GHOSTTAG_SECURITY_CORE_H

