// Define Windows 7 as the minimum target to ensure modern APIs (like GlobalMemoryStatusEx) are exposed
#define _WIN32_WINNT 0x0601

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>
#include <cwchar>
#include <cctype>
#include <fstream>
#include <numeric>
#include <cmath>
// MinGW/GCC headers for CPU intrinsics
#include <cpuid.h>
#include <x86intrin.h>
// Windows API headers
// windows.h includes almost everything we need.
// Removed sysinfoapi.h as it causes issues on some MinGW setups.
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

// Linker directives for MinGW (Optional, but good practice if supported)
// If these don't work, you must use the -l flags in the terminal: -liphlpapi
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "user32.lib")

class VMDetector
{
private:
    // Helper to lower-case strings for easy comparison
    std::string toLower(const std::string &str)
    {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c)
                       { return std::tolower(c); });
        return lower;
    }

    // Helper for safe Registry Reading
    bool checkRegistryKey(HKEY root, const char *path, const char *valueName, const char *searchStr)
    {
        HKEY hKey;
        // Open key with KEY_READ access
        if (RegOpenKeyExA(root, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            char buffer[1024]; // Use a larger buffer
            DWORD bufferSize = sizeof(buffer);
            DWORD type;

            // Query the value
            if (RegQueryValueExA(hKey, valueName, NULL, &type, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS)
            {
                if (type == REG_SZ && bufferSize > 0)
                {
                    // Convert buffer to string and lower case for search
                    std::string data = toLower(std::string(buffer));
                    std::string search = toLower(std::string(searchStr));

                    if (data.find(search) != std::string::npos)
                    {
                        RegCloseKey(hKey);
                        return true;
                    }
                }
            }
            RegCloseKey(hKey);
        }
        return false;
    }

public:
    // --- WRAPPER FUNCTIONS ---
    
    // Phase 1: Passive Checks (One-time startup)
    void runPassiveChecks(std::vector<std::string>& passive_threats) {
        // P1: Files (Common Paths)
        if (checkCommonPaths()) passive_threats.push_back("VM Directories Found (Common Paths)");
        
        // P2: Mac Address (OUI)
        if (checkMacAddress()) passive_threats.push_back("Suspicious MAC Address (VM OUI)");
        
        // P3: Installed Software (Registry Enumeration - categorized as Passive/Recon)
        if (checkInstalledSoftware()) passive_threats.push_back("VM Software Installed");
    }

    // Phase 2: Active Checks (Monitoring Loop)
    // Splits threats into Hard (Verdict: VM) and Soft (Verdict: Suspicious)
    // Calculates a weighted confidence score for Soft checks (Total 100)
    void runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score) {
        
        // --- HARD CHECKS (Phase 2A) ---
        
        // H1: RDTSC Instruction (Availability/Timing - Heavy)
        int rdtscStatus = checkRDTSCTiming();
        if (rdtscStatus == 2) active_hard.push_back("Critical: RDTSC Timing (Heavy Virtualization)");

        // H2: RDTSC Timing Attack (Generic Active Check logic often lumps these, separating purely for structure)
        // (Handled above by checkRDTSCTiming return code 2)

        // H3: CPUID & Brand Strings
        if (checkCPUIDHypervisorBit()) {
             std::string vendor = getHypervisorVendor();
             if (!vendor.empty()) active_soft.push_back("Critical: CPUID Vendor (" + vendor + ")");
        }
        std::string cpuBrand = checkCPUBrand();
        if (!cpuBrand.empty()) active_hard.push_back("Critical: CPU Brand (" + cpuBrand + ")");

        // H4: VMware I/O (Backdoor)
        if (checkVMwareBackdoor()) active_hard.push_back("Critical: VMware Backdoor Port Open");

        // H5: Hypervisor Drivers
        if (checkDriverFiles()) active_hard.push_back("Critical: Hypervisor Driver Files Loaded");

        // H6: VM Registry Keys (Specific Artifacts)
        if (checkRegistryArtifacts()) active_hard.push_back("Critical: VM Registry Keys Found");
        
        // Process Detection (Hard - Tools)
        if (checkProcesses()) active_hard.push_back("Critical: VM Tools/Process Detected");


        // --- SOFT CHECKS (Phase 2B) & SCORING ---
        // Total Score Max: 100
        
        // S1: RDTSC Jitter / Latency (Variance)
        // Score Weight: 40
        if (rdtscStatus == 1) {
            active_soft.push_back("Suspicious: RDTSC Variance/Jitter");
            confidence_score += 40;
        }

        // S2: Suspiciously Low Specs
        // Score Weight: 30
        if (checkLowSpecs()) {
            active_soft.push_back("Suspicious: Low System Specs (RAM/Cores)");
            confidence_score += 30;
        }

        // S3: Low Disk Size
        // Score Weight: 30
        if (checkDiskSize()) {
            active_soft.push_back("Suspicious: Small Disk Size (<60GB)");
            confidence_score += 30;
        }
    }

    // 1. CPUID Hypervisor Bit (The Standard Check)
    bool checkCPUIDHypervisorBit()
    {
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        {
            return (ecx & (1 << 31)) != 0;
        }
        return false;
    }

    // 2. Hypervisor Vendor String (The Name Tag)
    std::string getHypervisorVendor()
    {
        unsigned int eax, ebx, ecx, edx;
        // Leaf 0x40000000 is standard for Hypervisor Info
        if (__get_cpuid(0x40000000, &eax, &ebx, &ecx, &edx))
        {
            char vendor[13];
            memcpy(vendor, &ebx, 4);
            memcpy(vendor + 4, &ecx, 4);
            memcpy(vendor + 8, &edx, 4);
            vendor[12] = '\0';
            return std::string(vendor);
        }
        return "";
    }

    // 3. RDTSC Timing Attack (The Speed Trap)
    int checkRDTSCTiming()
    {
        unsigned int eax, ebx, ecx, edx;
        unsigned long long t1, t2;
        std::vector<unsigned long long> deltas;
        int iterations = 100;

        // 1. Warmup Phase
        // Execute CPUID a few times to ensure instruction cache is hot
        // and the CPU frequency is ramped up (wake from idle).
        for (int i = 0; i < 10; i++)
            __get_cpuid(1, &eax, &ebx, &ecx, &edx);

        // 2. Measurement Phase
        for (int i = 0; i < iterations; i++)
        {
            t1 = __rdtsc();
            __get_cpuid(1, &eax, &ebx, &ecx, &edx); // VM Exit
            t2 = __rdtsc();

            unsigned long long delta = t2 - t1;

            // Filter context switches (outliers > 50,000 cycles)
            if (delta < 50000)
            {
                deltas.push_back(delta);
            }
            Sleep(0); // Yield execution slice to keep OS happy
        }

        if (deltas.empty())
            return 0;

        // 3. Statistical Analysis
        unsigned long long sum = std::accumulate(deltas.begin(), deltas.end(), 0ULL);
        double average = static_cast<double>(sum) / deltas.size();

        double variance_sum = 0.0;
        for (unsigned long long val : deltas)
        {
            variance_sum += (val - average) * (val - average);
        }
        double variance = variance_sum / deltas.size();
        double std_dev = std::sqrt(variance);

        // --- CALIBRATED SCORING ---

        // CHECK A: Extreme Latency (The "Heavy" VM Check) - HARD CHECK
        // Native/VBS is usually 1,000 - 4,000 cycles.
        // VirtualBox/VMware/Emulators are often > 7,000 - 10,000+.
        // We set threshold to 6,000 to be safe from false positives on Host.
        if (average > 7000)
        {
            return 2; // Critical: Heavy Virtualization
        }

        // CHECK B: High Variance (The "Time Cheat" Check) - SOFT CHECK
        // Real hardware is consistent.
        // Cheating hypervisors trying to subtract cycles often introduce math errors/jitter.
        // If Standard Deviation is high (> 15% of average), it's suspicious.
        if (std_dev > 500 && std_dev > (average * 0.15))
        {
            return 1; // Warning: High Variance
        }

        // CHECK C: Time Cheating (Too Fast) - SOFT CHECK (could be hard, but usually implies manipulation)
        // If average is < 100 cycles, it's impossible for a CPUID instruction
        // (which is complex). It means someone is subtracting time manually.
        if (average < 100)
        {
            return 1; // Warning: Impossible Timing (Time Cheat)
        }

        return 0; // Clean
    }

    // 4. MAC Address & Adapter Name Check (Comprehensive)
    bool checkMacAddress()
    {
        ULONG outBufLen = 15000;
        std::vector<unsigned char> buffer(outBufLen);
        PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

        if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW)
        {
            buffer.resize(outBufLen);
            pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
        }

        bool found = false;

        if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR)
        {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter)
            {
                // --- OUI CHECK (First 3 bytes) ---
                if (pAdapter->AddressLength >= 3)
                {
                    // VMware
                    if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x05 && pAdapter->Address[2] == 0x69)
                        found = true;
                    else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x0C && pAdapter->Address[2] == 0x29)
                        found = true;
                    else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x50 && pAdapter->Address[2] == 0x56)
                        found = true;
                    else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x1C && pAdapter->Address[2] == 0x14)
                        found = true;
                    // VirtualBox
                    else if (pAdapter->Address[0] == 0x08 && pAdapter->Address[1] == 0x00 && pAdapter->Address[2] == 0x27)
                        found = true;
                    // Parallels
                    else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x1C && pAdapter->Address[2] == 0x42)
                        found = true;
                    // Xen
                    else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x16 && pAdapter->Address[2] == 0x3E)
                        found = true;
                    // Hyper-V
                    // else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x15 && pAdapter->Address[2] == 0x5D)
                    //     found = true;
                }

                // --- ADAPTER NAME CHECK (Host-Side Detection) ---
                std::string desc = pAdapter->Description;
                std::string lowerDesc = toLower(desc);

                if (lowerDesc.find("virtualbox") != std::string::npos ||
                    lowerDesc.find("vmware") != std::string::npos ||
                    lowerDesc.find("qemu") != std::string::npos ||
                    lowerDesc.find("virtio") != std::string::npos ||
                    lowerDesc.find("hyper-v") != std::string::npos ||
                    lowerDesc.find("parallels") != std::string::npos ||
                    lowerDesc.find("radmin") != std::string::npos || // Radmin VPN
                    lowerDesc.find("tuntap") != std::string::npos)
                { // Generic TunTap (often used by emulators)
                    found = true;
                }

                pAdapter = pAdapter->Next;
            }
        }
        return found;
    }

    // 5. Comprehensive Registry Scan (Extensive)
    bool checkRegistryArtifacts()
    {
        // --- SYSTEM BIOS VERSIONS ---
        const char *sysPath = "HARDWARE\\DESCRIPTION\\System";
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "SystemBiosVersion", "vbox"))
            return true;
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "SystemBiosVersion", "bochs"))
            return true;
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "SystemBiosVersion", "qemu"))
            return true;
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "SystemBiosVersion", "virtualbox"))
            return true;
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "SystemBiosVersion", "parallels"))
            return true;
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "VideoBiosVersion", "virtualbox"))
            return true;
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "VideoBiosVersion", "vmware"))
            return true;

        // --- SCSI / DISK IDENTIFIERS ---
        const char *scsiPath = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0";
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, scsiPath, "Identifier", "vbox"))
            return true;
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, scsiPath, "Identifier", "vmware"))
            return true;
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, scsiPath, "Identifier", "qemu"))
            return true;
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, scsiPath, "Identifier", "red hat"))
            return true; // KVM VirtIO
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, scsiPath, "Identifier", "xen"))
            return true;

        // --- SOFTWARE KEYS ---
        // Oracle VirtualBox
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", "Version", ""))
            return true;
        // VMware
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", "InstallPath", ""))
            return true;
        // Wine
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Wine", "Version", ""))
            return true;
        // Xen
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Citrix\\XenTools", "InstallDir", ""))
            return true;
        // BlueStacks (Android Emulator)
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\BlueStacks", "InstallDir", ""))
            return true;
        // Sandboxie
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Sandboxie", "Version", ""))
            return true;

        // --- HYPER-V SPECIFIC ---
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", "VirtualMachineName", ""))
            return true;
        if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Hyper-V", "GuestInstallerVersion", ""))
            return true;

        return false;
    }

    // 6. Driver & File Check (Extensive)
    bool checkDriverFiles()
    {
        std::vector<std::string> paths = {
            // VirtualBox
            "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
            "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
            "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
            "C:\\Windows\\System32\\drivers\\VBoxVideo.sys",

            // VMware
            "C:\\Windows\\System32\\drivers\\vm3dmp.sys",
            "C:\\Windows\\System32\\drivers\\vmtools.sys",
            "C:\\Windows\\System32\\drivers\\vmmouse.sys",
            "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
            "C:\\Windows\\System32\\drivers\\vmmemctl.sys",

            // KVM / QEMU (VirtIO)
            "C:\\Windows\\System32\\drivers\\vioinput.sys",
            "C:\\Windows\\System32\\drivers\\virtio.sys",
            "C:\\Windows\\System32\\drivers\\viostor.sys",
            "C:\\Windows\\System32\\drivers\\viocrypt.sys",
            "C:\\Windows\\System32\\drivers\\vioser.sys",
            "C:\\Windows\\System32\\drivers\\netkvm.sys",

            // Parallels
            "C:\\Windows\\System32\\drivers\\prl_fs.sys",
            "C:\\Windows\\System32\\drivers\\prl_mouse.sys",
            "C:\\Windows\\System32\\drivers\\prl_time.sys",
            "C:\\Windows\\System32\\drivers\\prl_video.sys",

            // Xen
            "C:\\Windows\\System32\\drivers\\xenaudio.sys",
            "C:\\Windows\\System32\\drivers\\xenbus.sys",
            "C:\\Windows\\System32\\drivers\\xenhide.sys",
            "C:\\Windows\\System32\\drivers\\xenfilt.sys",
            "C:\\Windows\\System32\\drivers\\xennet.sys",

            // Sandboxie
            "C:\\Windows\\System32\\drivers\\sbiedrv.sys"};

        for (const auto &path : paths)
        {
            std::ifstream f(path);
            if (f.good())
                return true;
        }
        return false;
    }

    // 7. Low Specs Heuristic (The Poverty Check)
    bool checkLowSpecs()
    {
        // Check RAM
        MEMORYSTATUSEX statex;
        statex.dwLength = sizeof(statex);
        GlobalMemoryStatusEx(&statex);
        // Warning if RAM < 3GB
        bool lowRAM = statex.ullTotalPhys < (3ULL * 1024 * 1024 * 1024);

        // Check Cores
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        bool lowCores = sysInfo.dwNumberOfProcessors < 2;

        return lowRAM || lowCores;
    }

    // 8. Disk Size Heuristic
    bool checkDiskSize()
    {
        ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
        // Check C: drive
        if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes))
        {
            // Convert bytes to GB
            unsigned long long totalGB = totalNumberOfBytes.QuadPart / (1024 * 1024 * 1024);
            if (totalGB < 60)
            { // If C: drive is smaller than 60GB, it's suspicious
                return true;
            }
        }
        return false;
    }

    // 9. Process & Tool Detection (Extensive)
    bool checkProcesses()
    {
        std::vector<std::string> blacklisted = {
            // --- VIRTUAL MACHINE (HOST & GUEST) ---
            // VirtualBox
            "vboxservice.exe", "vboxtray.exe", "vboxheadless.exe",
            "virtualbox.exe", "virtualboxvm.exe", "vboxsvc.exe",
            // VMware
            "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "vmacthlp.exe",
            "vmware.exe", "vmware-authd.exe", "vmware-hostd.exe",
            // QEMU / KVM
            "qemu-ga.exe", "qemu-system-x86_64.exe", "qemu-system-i386.exe",
            // Parallels
            "prl_cc.exe", "prl_tools.exe",
            // Xen
            "xenservice.exe",
            // Sandboxie
            "sandboxiedcomlaunch.exe", "sandboxierpcss.exe",

            // --- ANDROID EMULATORS (Often used for cheating) ---
            "hd-player.exe", "bluestacks.exe", "hd-agent.exe", // BlueStacks
            "nox.exe", "noxvmhandle.exe",                      // Nox
            "dnplayer.exe", "ld9boxheadless.exe",              // LDPlayer
            "meMuHeadless.exe",                                // Memu

            // --- REMOTE ACCESS & SCREEN SHARING ---
            "teamviewer.exe", "teamviewer_service.exe", "tv_w32.exe", "tv_x64.exe",
            "anydesk.exe",
            "logmein.exe", "lmiguardian.exe",
            "g2mcomm.exe", // GoToMeeting
            "mikogo-bin.exe",
            "join.me.console.exe",
            "vncviewer.exe", "realvnc.exe", "tvnserver.exe", "winvnc.exe",
            "tightvnc.exe", "ultravnc.exe",
            "chrome remote desktop.exe", "remotepc.exe",
            "rdpclip.exe", // RDP Clipboard Monitor
            "mstsc.exe",   // Microsoft Remote Desktop

            // --- ANALYSIS & CHEAT TOOLS ---
            "wireshark.exe", "dumpcap.exe", "tshark.exe",
            "procmon.exe", "procexp.exe", "processhacker.exe",
            "fiddler.exe", "httpdebuggerui.exe",
            "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "immunitydebugger.exe",
            "windbg.exe",
            "cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheatengine.exe"};

        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        if (Process32First(snapshot, &entry))
        {
            do
            {
                std::string currentProcess = entry.szExeFile;
                currentProcess = toLower(currentProcess);

                for (const auto &badProc : blacklisted)
                {
                    if (currentProcess == badProc)
                    {
                        CloseHandle(snapshot);
                        return true;
                    }
                }
            } while (Process32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
        return false;
    }

    // 10. CPU Brand String Check
    // Returns: string containing the detection (e.g., "QEMU Virtual CPU"), or empty string if clean.
    std::string checkCPUBrand()
    {
        unsigned int eax, ebx, ecx, edx;
        char brand[49]; // 3 calls * 16 bytes + 1 null terminator
        memset(brand, 0, sizeof(brand));

        // Check if extended functions are supported
        __get_cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
        if (eax < 0x80000004)
            return ""; // CPU too old or restricted

        // The Brand String is split across 3 leaves: 0x80000002, 0x80000003, 0x80000004
        std::vector<unsigned int> leaves = {0x80000002, 0x80000003, 0x80000004};

        for (int i = 0; i < 3; i++)
        {
            __get_cpuid(leaves[i], &eax, &ebx, &ecx, &edx);
            memcpy(brand + (i * 16), &eax, 4);
            memcpy(brand + (i * 16) + 4, &ebx, 4);
            memcpy(brand + (i * 16) + 8, &ecx, 4);
            memcpy(brand + (i * 16) + 12, &edx, 4);
        }

        std::string cpuName = std::string(brand);
        std::string lowerName = toLower(cpuName);

        // Check for forbidden keywords
        if (lowerName.find("qemu") != std::string::npos)
            return cpuName;
        if (lowerName.find("kvm") != std::string::npos)
            return cpuName;
        if (lowerName.find("vmware") != std::string::npos)
            return cpuName;
        if (lowerName.find("virtual") != std::string::npos)
            return cpuName;
        if (lowerName.find("xen") != std::string::npos)
            return cpuName;
        if (lowerName.find("innotek") != std::string::npos)
            return cpuName; // VirtualBox

        return ""; // Clean
    }

    // 11. Installed Software Scan (The "Smart Search")
    // Scans Windows "Uninstall" keys to find VM software installed in custom paths (e.g., D:\Tools\VirtualBox)
    bool checkInstalledSoftware()
    {
        std::vector<std::string> registryPaths = {
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" // 32-bit apps on 64-bit Windows
        };

        std::vector<HKEY> roots = {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER};

        for (HKEY root : roots)
        {
            for (const auto &regPath : registryPaths)
            {
                HKEY hKey;
                if (RegOpenKeyExA(root, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
                {
                    char subKeyName[256];
                    DWORD index = 0;
                    DWORD subKeyLen = sizeof(subKeyName);

                    // Iterate through all installed programs
                    while (RegEnumKeyExA(hKey, index, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
                    {
                        HKEY hSubKey;
                        std::string subKeyPath = regPath + "\\" + subKeyName;

                        if (RegOpenKeyExA(root, subKeyPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS)
                        {
                            char displayName[256];
                            DWORD dataSize = sizeof(displayName);

                            // Read "DisplayName" (e.g., "Oracle VM VirtualBox 7.0.12")
                            if (RegQueryValueExA(hSubKey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &dataSize) == ERROR_SUCCESS)
                            {
                                std::string name = toLower(std::string(displayName));

                                // Check against known keywords
                                if (name.find("virtualbox") != std::string::npos ||
                                    name.find("vmware") != std::string::npos ||
                                    name.find("qemu") != std::string::npos ||
                                    name.find("wireshark") != std::string::npos ||
                                    name.find("bluestacks") != std::string::npos ||
                                    name.find("nox player") != std::string::npos ||
                                    name.find("ldplayer") != std::string::npos ||
                                    name.find("sandboxie") != std::string::npos ||
                                    name.find("cheat engine") != std::string::npos)
                                {

                                    // std::cout << "[DEBUG] Found Installed Software: " << displayName << "\n";
                                    RegCloseKey(hSubKey);
                                    RegCloseKey(hKey);
                                    return true;
                                }
                            }
                            RegCloseKey(hSubKey);
                        }
                        index++;
                        subKeyLen = sizeof(subKeyName); // Reset buffer size
                    }
                    RegCloseKey(hKey);
                }
            }
        }
        return false;
    }

    // 12. Common Paths & Start Menu Scan (Upgraded)
    bool checkCommonPaths()
    {
        // 1. Get Environment Variables
        char progFiles[MAX_PATH];
        char progFilesX86[MAX_PATH];
        char userProfile[MAX_PATH];
        char allUsersProfile[MAX_PATH]; // C:\ProgramData

        if (!GetEnvironmentVariableA("ProgramFiles", progFiles, MAX_PATH))
            strcpy(progFiles, "C:\\Program Files");
        if (!GetEnvironmentVariableA("ProgramFiles(x86)", progFilesX86, MAX_PATH))
            strcpy(progFilesX86, "C:\\Program Files (x86)");
        if (!GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH))
            strcpy(userProfile, "C:\\Users\\Public");
        if (!GetEnvironmentVariableA("ALLUSERSPROFILE", allUsersProfile, MAX_PATH))
            strcpy(allUsersProfile, "C:\\ProgramData");

        std::vector<std::string> directories = {
            // --- Installation Directories ---
            std::string(progFiles) + "\\Oracle\\VirtualBox",
            std::string(progFilesX86) + "\\Oracle\\VirtualBox",
            std::string(progFiles) + "\\VMware\\VMware Workstation",
            std::string(progFilesX86) + "\\VMware\\VMware Workstation",
            std::string(progFiles) + "\\VMware\\VMware Player",
            std::string(progFiles) + "\\QEMU",
            std::string(progFiles) + "\\Sandboxie",
            std::string(progFiles) + "\\BlueStacks",
            std::string(progFiles) + "\\BlueStacks_nxt",
            std::string(progFiles) + "\\LDPlayer",
            std::string(progFiles) + "\\LDPlayer9",

            // --- Start Menu Shortcuts (The "Secret" Stash) ---
            // This is where your specific folder was located:
            std::string(allUsersProfile) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Oracle VM VirtualBox",
            std::string(allUsersProfile) + "\\Microsoft\\Windows\\Start Menu\\Programs\\VMware",
            std::string(allUsersProfile) + "\\Microsoft\\Windows\\Start Menu\\Programs\\QEMU",
            std::string(allUsersProfile) + "\\Microsoft\\Windows\\Start Menu\\Programs\\BlueStacks",
            std::string(allUsersProfile) + "\\Microsoft\\Windows\\Start Menu\\Programs\\LDPlayer",

            // --- User Artifacts ---
            std::string(userProfile) + "\\VirtualBox VMs",
            std::string(userProfile) + "\\.VirtualBox",
            std::string(userProfile) + "\\Documents\\Virtual Machines"};

        for (const auto &path : directories)
        {
            DWORD attrib = GetFileAttributesA(path.c_str());
            if (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY))
            {
                // std::cout << "[DEBUG] Found Directory: " << path << "\n";
                return true;
            }
        }
        return false;
    }

    // Static exception handler for the VMware check
    static LONG WINAPI VmwareExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
    {
        // If we get a "Privileged Instruction" error (0xC0000096), it means
        // we are on Real Hardware (or non-VMware) because the CPU blocked the I/O instruction.
        // We skip the instruction to prevent a crash.
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
        {
// Skip the instruction (IN EAX, DX is usually 1 byte, but we step safely)
#ifdef _WIN64
            ExceptionInfo->ContextRecord->Rip += 1;
#else
            ExceptionInfo->ContextRecord->Eip += 1;
#endif
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // 13. VMware Backdoor I/O Port Check (The "Knock" Check)
    // This attempts to communicate with the hypervisor directly.
    bool checkVMwareBackdoor()
    {
        bool isVMware = false;

        // Register a temporary crash handler
        PVOID handler = AddVectoredExceptionHandler(1, VmwareExceptionHandler);

        // Use low-level assembly to knock on the port
        try
        {
            unsigned int magic = 0x564D5868; // "VMXh"
            unsigned int command = 10;       // Get Version
            unsigned int port = 0x5658;      // "VX"

            unsigned int result_magic = 0;
            unsigned int result_rbx = 0;

            // --- FIXED ASSEMBLY BLOCK ---
            // We use constraints ("a", "c", "d") to tell the compiler exactly
            // where to put the variables BEFORE the assembly runs.
            __asm__ volatile(
                "in %%dx, %%eax;"     // The actual port read
                : "=a"(result_magic), // Output 1: EAX -> result_magic
                  "=b"(result_rbx)    // Output 2: EBX -> result_rbx
                : "a"(magic),         // Input 1: magic -> EAX
                  "c"(command),       // Input 2: command -> ECX
                  "d"(port)           // Input 3: port -> EDX
                :                     // No clobbers needed
            );
            // -----------------------------

            // If the port replied with the Magic Number in EBX, it's VMware
            if (result_rbx == 0x564D5868)
            {
                isVMware = true;
            }
        }
        catch (...)
        {
            // Checking failed
        }

        // Remove the crash handler
        RemoveVectoredExceptionHandler(handler);
        return isVMware;
    }
};