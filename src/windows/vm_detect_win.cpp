#define _WIN32_WINNT 0x0601

#include "../../include/vm_detect.hpp"
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
#include <cpuid.h>
#include <x86intrin.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "user32.lib")

// Helper methods (File-local / private to implementation)
std::string toLower(const std::string &str)
{
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c)
                   { return std::tolower(c); });
    return lower;
}

bool checkRegistryKey(HKEY root, const char *path, const char *valueName, const char *searchStr)
{
    HKEY hKey;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        char buffer[1024];
        DWORD bufferSize = sizeof(buffer);
        DWORD type;
        if (RegQueryValueExA(hKey, valueName, NULL, &type, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS)
        {
            if (type == REG_SZ && bufferSize > 0)
            {
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

// Internal Check Functions
bool checkCommonPaths();
bool checkMacAddress();
bool checkInstalledSoftware();
int checkRDTSCTiming();
bool checkCPUIDHypervisorBit();
std::string getHypervisorVendor();
std::string checkCPUBrand();
bool checkVMwareBackdoor();
bool checkDriverFiles();
bool checkRegistryArtifacts();
bool checkProcesses();
bool checkLowSpecs();
bool checkDiskSize();

// --- Implementation of VMDetector Class defined in header ---

void VMDetector::runPassiveChecks(std::vector<std::string>& passive_threats) {
    if (checkCommonPaths()) passive_threats.push_back("VM Directories Found (Common Paths)");
    if (checkMacAddress()) passive_threats.push_back("Suspicious MAC Address (VM OUI)");
    if (checkInstalledSoftware()) passive_threats.push_back("VM Software Installed");
}

void VMDetector::runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score) {
    int rdtscStatus = checkRDTSCTiming();
    if (rdtscStatus == 2) active_hard.push_back("Critical: RDTSC Timing (Heavy Virtualization)");

    if (checkCPUIDHypervisorBit()) {
            std::string vendor = getHypervisorVendor();
            if (!vendor.empty()) active_soft.push_back("Critical: CPUID Vendor (" + vendor + ")");
    }
    std::string cpuBrand = checkCPUBrand();
    if (!cpuBrand.empty()) active_hard.push_back("Critical: CPU Brand (" + cpuBrand + ")");

    if (checkVMwareBackdoor()) active_hard.push_back("Critical: VMware Backdoor Port Open");

    if (checkDriverFiles()) active_hard.push_back("Critical: Hypervisor Driver Files Loaded");

    if (checkRegistryArtifacts()) active_hard.push_back("Critical: VM Registry Keys Found");
    
    if (checkProcesses()) active_hard.push_back("Critical: VM Tools/Process Detected");

    if (rdtscStatus == 1) {
        active_soft.push_back("Suspicious: RDTSC Variance/Jitter");
        confidence_score += 40;
    }

    if (checkLowSpecs()) {
        active_soft.push_back("Suspicious: Low System Specs (RAM/Cores)");
        confidence_score += 30;
    }

    if (checkDiskSize()) {
        active_soft.push_back("Suspicious: Small Disk Size (<60GB)");
        confidence_score += 30;
    }
}

// --- Internal Function Definitions (Copied from original) ---

bool checkCPUIDHypervisorBit()
{
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx))
    {
        return (ecx & (1 << 31)) != 0;
    }
    return false;
}

std::string getHypervisorVendor()
{
    unsigned int eax, ebx, ecx, edx;
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

int checkRDTSCTiming()
{
    unsigned int eax, ebx, ecx, edx;
    unsigned long long t1, t2;
    std::vector<unsigned long long> deltas;
    int iterations = 100;

    for (int i = 0; i < 10; i++)
        __get_cpuid(1, &eax, &ebx, &ecx, &edx);

    for (int i = 0; i < iterations; i++)
    {
        t1 = __rdtsc();
        __get_cpuid(1, &eax, &ebx, &ecx, &edx);
        t2 = __rdtsc();

        unsigned long long delta = t2 - t1;

        if (delta < 50000)
        {
            deltas.push_back(delta);
        }
        Sleep(0);
    }

    if (deltas.empty())
        return 0;

    unsigned long long sum = std::accumulate(deltas.begin(), deltas.end(), 0ULL);
    double average = static_cast<double>(sum) / deltas.size();

    double variance_sum = 0.0;
    for (unsigned long long val : deltas)
    {
        variance_sum += (val - average) * (val - average);
    }
    double variance = variance_sum / deltas.size();
    double std_dev = std::sqrt(variance);

    if (average > 7000)
    {
        return 2;
    }

    if (std_dev > 500 && std_dev > (average * 0.15))
    {
        return 1; 
    }

    if (average < 100)
    {
        return 1; 
    }

    return 0; 
}

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
            if (pAdapter->AddressLength >= 3)
            {
                if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x05 && pAdapter->Address[2] == 0x69) found = true;
                else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x0C && pAdapter->Address[2] == 0x29) found = true;
                else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x50 && pAdapter->Address[2] == 0x56) found = true;
                else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x1C && pAdapter->Address[2] == 0x14) found = true;
                else if (pAdapter->Address[0] == 0x08 && pAdapter->Address[1] == 0x00 && pAdapter->Address[2] == 0x27) found = true;
                else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x1C && pAdapter->Address[2] == 0x42) found = true;
                else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x16 && pAdapter->Address[2] == 0x3E) found = true;
            }

            std::string desc = pAdapter->Description;
            std::string lowerDesc = toLower(desc);

            if (lowerDesc.find("virtualbox") != std::string::npos ||
                lowerDesc.find("vmware") != std::string::npos ||
                lowerDesc.find("qemu") != std::string::npos ||
                lowerDesc.find("virtio") != std::string::npos ||
                lowerDesc.find("hyper-v") != std::string::npos ||
                lowerDesc.find("parallels") != std::string::npos ||
                lowerDesc.find("radmin") != std::string::npos ||
                lowerDesc.find("tuntap") != std::string::npos)
            { 
                found = true;
            }

            pAdapter = pAdapter->Next;
        }
    }
    return found;
}

bool checkRegistryArtifacts()
{
    const char *sysPath = "HARDWARE\\DESCRIPTION\\System";
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "SystemBiosVersion", "vbox")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "SystemBiosVersion", "bochs")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "SystemBiosVersion", "qemu")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "SystemBiosVersion", "virtualbox")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "SystemBiosVersion", "parallels")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "VideoBiosVersion", "virtualbox")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, sysPath, "VideoBiosVersion", "vmware")) return true;

    const char *scsiPath = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0";
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, scsiPath, "Identifier", "vbox")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, scsiPath, "Identifier", "vmware")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, scsiPath, "Identifier", "qemu")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, scsiPath, "Identifier", "red hat")) return true; 
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, scsiPath, "Identifier", "xen")) return true;

    if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", "Version", "")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", "InstallPath", "")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Wine", "Version", "")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Citrix\\XenTools", "InstallDir", "")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\BlueStacks", "InstallDir", "")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Sandboxie", "Version", "")) return true;

    if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", "VirtualMachineName", "")) return true;
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Hyper-V", "GuestInstallerVersion", "")) return true;

    return false;
}

bool checkDriverFiles()
{
    std::vector<std::string> paths = {
        "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
        "C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
        "C:\\Windows\\System32\\drivers\\vm3dmp.sys",
        "C:\\Windows\\System32\\drivers\\vmtools.sys",
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        "C:\\Windows\\System32\\drivers\\vmmemctl.sys",
        "C:\\Windows\\System32\\drivers\\vioinput.sys",
        "C:\\Windows\\System32\\drivers\\virtio.sys",
        "C:\\Windows\\System32\\drivers\\viostor.sys",
        "C:\\Windows\\System32\\drivers\\viocrypt.sys",
        "C:\\Windows\\System32\\drivers\\vioser.sys",
        "C:\\Windows\\System32\\drivers\\netkvm.sys",
        "C:\\Windows\\System32\\drivers\\prl_fs.sys",
        "C:\\Windows\\System32\\drivers\\prl_mouse.sys",
        "C:\\Windows\\System32\\drivers\\prl_time.sys",
        "C:\\Windows\\System32\\drivers\\prl_video.sys",
        "C:\\Windows\\System32\\drivers\\xenaudio.sys",
        "C:\\Windows\\System32\\drivers\\xenbus.sys",
        "C:\\Windows\\System32\\drivers\\xenhide.sys",
        "C:\\Windows\\System32\\drivers\\xenfilt.sys",
        "C:\\Windows\\System32\\drivers\\xennet.sys",
        "C:\\Windows\\System32\\drivers\\sbiedrv.sys"};

    for (const auto &path : paths)
    {
        std::ifstream f(path);
        if (f.good())
            return true;
    }
    return false;
}

bool checkLowSpecs()
{
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    bool lowRAM = statex.ullTotalPhys < (3ULL * 1024 * 1024 * 1024);

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    bool lowCores = sysInfo.dwNumberOfProcessors < 2;

    return lowRAM || lowCores;
}

bool checkDiskSize()
{
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes))
    {
        unsigned long long totalGB = totalNumberOfBytes.QuadPart / (1024 * 1024 * 1024);
        if (totalGB < 60)
        { 
            return true;
        }
    }
    return false;
}

bool checkProcesses()
{
    std::vector<std::string> blacklisted = {
        "vboxservice.exe", "vboxtray.exe", "vboxheadless.exe",
        "virtualbox.exe", "virtualboxvm.exe", "vboxsvc.exe",
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "vmacthlp.exe",
        "vmware.exe", "vmware-authd.exe", "vmware-hostd.exe",
        "qemu-ga.exe", "qemu-system-x86_64.exe", "qemu-system-i386.exe",
        "prl_cc.exe", "prl_tools.exe",
        "xenservice.exe",
        "sandboxiedcomlaunch.exe", "sandboxierpcss.exe",
        "hd-player.exe", "bluestacks.exe", "hd-agent.exe", 
        "nox.exe", "noxvmhandle.exe",                      
        "dnplayer.exe", "ld9boxheadless.exe",              
        "meMuHeadless.exe",                                
        "teamviewer.exe", "teamviewer_service.exe", "tv_w32.exe", "tv_x64.exe",
        "anydesk.exe",
        "logmein.exe", "lmiguardian.exe",
        "g2mcomm.exe", 
        "mikogo-bin.exe",
        "join.me.console.exe",
        "vncviewer.exe", "realvnc.exe", "tvnserver.exe", "winvnc.exe",
        "tightvnc.exe", "ultravnc.exe",
        "chrome remote desktop.exe", "remotepc.exe",
        "rdpclip.exe", 
        "mstsc.exe",   
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

std::string checkCPUBrand()
{
    unsigned int eax, ebx, ecx, edx;
    char brand[49]; 
    memset(brand, 0, sizeof(brand));

    __get_cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
    if (eax < 0x80000004)
        return ""; 

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

    if (lowerName.find("qemu") != std::string::npos) return cpuName;
    if (lowerName.find("kvm") != std::string::npos) return cpuName;
    if (lowerName.find("vmware") != std::string::npos) return cpuName;
    if (lowerName.find("virtual") != std::string::npos) return cpuName;
    if (lowerName.find("xen") != std::string::npos) return cpuName;
    if (lowerName.find("innotek") != std::string::npos) return cpuName; 

    return ""; 
}

bool checkInstalledSoftware()
{
    std::vector<std::string> registryPaths = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" 
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

                while (RegEnumKeyExA(hKey, index, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
                {
                    HKEY hSubKey;
                    std::string subKeyPath = regPath + "\\" + subKeyName;

                    if (RegOpenKeyExA(root, subKeyPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS)
                    {
                        char displayName[256];
                        DWORD dataSize = sizeof(displayName);

                        if (RegQueryValueExA(hSubKey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &dataSize) == ERROR_SUCCESS)
                        {
                            std::string name = toLower(std::string(displayName));

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
                                RegCloseKey(hSubKey);
                                RegCloseKey(hKey);
                                return true;
                            }
                        }
                        RegCloseKey(hSubKey);
                    }
                    index++;
                    subKeyLen = sizeof(subKeyName); 
                }
                RegCloseKey(hKey);
            }
        }
    }
    return false;
}

bool checkCommonPaths()
{
    char progFiles[MAX_PATH];
    char progFilesX86[MAX_PATH];
    char userProfile[MAX_PATH];
    char allUsersProfile[MAX_PATH]; 

    if (!GetEnvironmentVariableA("ProgramFiles", progFiles, MAX_PATH))
        strcpy(progFiles, "C:\\Program Files");
    if (!GetEnvironmentVariableA("ProgramFiles(x86)", progFilesX86, MAX_PATH))
        strcpy(progFilesX86, "C:\\Program Files (x86)");
    if (!GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH))
        strcpy(userProfile, "C:\\Users\\Public");
    if (!GetEnvironmentVariableA("ALLUSERSPROFILE", allUsersProfile, MAX_PATH))
        strcpy(allUsersProfile, "C:\\ProgramData");

    std::vector<std::string> directories = {
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

        std::string(allUsersProfile) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Oracle VM VirtualBox",
        std::string(allUsersProfile) + "\\Microsoft\\Windows\\Start Menu\\Programs\\VMware",
        std::string(allUsersProfile) + "\\Microsoft\\Windows\\Start Menu\\Programs\\QEMU",
        std::string(allUsersProfile) + "\\Microsoft\\Windows\\Start Menu\\Programs\\BlueStacks",
        std::string(allUsersProfile) + "\\Microsoft\\Windows\\Start Menu\\Programs\\LDPlayer",

        std::string(userProfile) + "\\VirtualBox VMs",
        std::string(userProfile) + "\\.VirtualBox",
        std::string(userProfile) + "\\Documents\\Virtual Machines"};

    for (const auto &path : directories)
    {
        DWORD attrib = GetFileAttributesA(path.c_str());
        if (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY))
        {
            return true;
        }
    }
    return false;
}

static LONG WINAPI VmwareExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
    {
#ifdef _WIN64
        ExceptionInfo->ContextRecord->Rip += 1;
#else
        ExceptionInfo->ContextRecord->Eip += 1;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool checkVMwareBackdoor()
{
    bool isVMware = false;
    PVOID handler = AddVectoredExceptionHandler(1, VmwareExceptionHandler);
    try
    {
        unsigned int magic = 0x564D5868; 
        unsigned int command = 10;       
        unsigned int port = 0x5658;      

        unsigned int result_magic = 0;
        unsigned int result_rbx = 0;

        __asm__ volatile(
            "in %%dx, %%eax;"     
            : "=a"(result_magic), 
                "=b"(result_rbx)    
            : "a"(magic),         
                "c"(command),       
                "d"(port)           
            :                     
        );

        if (result_rbx == 0x564D5868)
        {
            isVMware = true;
        }
    }
    catch (...)
    {
    }

    RemoveVectoredExceptionHandler(handler);
    return isVMware;
}
