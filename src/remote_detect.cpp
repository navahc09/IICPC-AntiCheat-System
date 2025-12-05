// Final Remote Access Detection Tool (Active vs Passive)
// Compile with: g++ -o remote_detect.exe remote_detect.cpp -lws2_32 -liphlpapi -lwtsapi32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <wtsapi32.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem> // For checking file existence

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Wtsapi32.lib")

#ifndef WTSClientProtocolType
#define WTSClientProtocolType (WTS_INFO_CLASS)16
#endif

// Enum to track the threat level of a specific tool
enum ThreatLevel
{
    CLEAN = 0,
    PASSIVE, // Installed but not running
    ACTIVE   // Running right now
};

struct RATInfo
{
    std::string name;
    std::vector<std::string> processes;
    std::vector<std::string> services;
    std::vector<int> ports;
    std::vector<std::string> windowTitles;
    std::vector<std::string> installPaths; // New: Passive file checks
};

class RemoteDetector
{
private:
    // Expanded Database with File Paths
    std::vector<RATInfo> ratList = {
        {"AnyDesk", {"AnyDesk.exe"}, {"AnyDesk"}, {7070, 6568}, {"AnyDesk"}, {"C:\\Program Files (x86)\\AnyDesk", "C:\\Program Files\\AnyDesk"}},
        {"TeamViewer", {"TeamViewer.exe", "TeamViewer_Service.exe"}, {"TeamViewer"}, {5938}, {"TeamViewer"}, {"C:\\Program Files\\TeamViewer", "C:\\Program Files (x86)\\TeamViewer"}},
        {"RustDesk", {"rustdesk.exe"}, {"RustDesk"}, {21114, 21115, 21116, 21117}, {"RustDesk"}, {"C:\\Program Files\\RustDesk"}},
        {"Chrome Remote Desktop", {"remoting_host.exe"}, {"chromoting"}, {}, {"Chrome Remote Desktop"}, {"C:\\Program Files (x86)\\Google\\Chrome Remote Desktop"}},
        {"UltraViewer", {"UltraViewer_Desktop.exe"}, {"UltraViewer"}, {5650}, {"UltraViewer"}, {"C:\\Program Files (x86)\\UltraViewer"}},
        {"VNC Server", {"winvnc.exe", "tvnserver.exe", "vncserver.exe"}, {"uvnc_service", "tvnserver"}, {5900, 5800}, {"VNC"}, {"C:\\Program Files\\RealVNC", "C:\\Program Files\\TightVNC"}},
        {"LogMeIn", {"LogMeIn.exe", "LMIGuardian.exe"}, {"LogMeIn"}, {2002}, {"LogMeIn"}, {"C:\\Program Files (x86)\\LogMeIn"}}};

    // Helper: Case insensitive string search
    inline bool containsString(const std::string &haystack, const std::string &needle)
    {
        auto it = std::search(
            haystack.begin(), haystack.end(),
            needle.begin(), needle.end(),
            [](char ch1, char ch2)
            { return std::toupper(ch1) == std::toupper(ch2); });
        return (it != haystack.end());
    }

    // 1. Process Check (Active)
    bool isProcessRunning(const std::string &target)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return false;
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe))
        {
            do
            {
                if (containsString(pe.szExeFile, target))
                {
                    CloseHandle(snap);
                    return true;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
        return false;
    }

    // 2. Service State Check (Active vs Passive)
    ThreatLevel checkServiceState(const std::string &name)
    {
        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!scm)
            return CLEAN;

        SC_HANDLE svc = OpenService(scm, name.c_str(), SERVICE_QUERY_STATUS);
        ThreatLevel status = CLEAN;

        if (svc)
        {
            // Service exists -> At least PASSIVE
            status = PASSIVE;
            SERVICE_STATUS_PROCESS ssp;
            DWORD bytesNeeded;
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
            {
                if (ssp.dwCurrentState == SERVICE_RUNNING)
                {
                    status = ACTIVE;
                }
            }
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
        return status;
    }

    // 3. File/Path Check (Passive)
    bool pathExists(const std::string &path)
    {
        DWORD attrib = GetFileAttributesA(path.c_str());
        return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
    }

    // 4. Registry Uninstall Check (Passive)
    bool checkRegistryInstall(const std::string &appName)
    {
        std::string regPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            char subKeyName[256];
            DWORD index = 0;
            DWORD subKeyLen = sizeof(subKeyName);
            while (RegEnumKeyExA(hKey, index++, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
            {
                HKEY hSubKey;
                std::string subKeyPath = regPath + "\\" + subKeyName;
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKeyPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS)
                {
                    char displayName[256];
                    DWORD dataSize = sizeof(displayName);
                    if (RegQueryValueExA(hSubKey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &dataSize) == ERROR_SUCCESS)
                    {
                        if (containsString(displayName, appName))
                        {
                            RegCloseKey(hSubKey);
                            RegCloseKey(hKey);
                            return true;
                        }
                    }
                    RegCloseKey(hSubKey);
                }
                subKeyLen = sizeof(subKeyName);
            }
            RegCloseKey(hKey);
        }
        return false;
    }

    // 5. Window Title Check (Active - Soft)
    bool windowTitleExists(const std::string &titleSnippet)
    {
        bool found = false;
        // FIX: Create a named pair variable so we can take its address safely
        std::pair<std::string, bool *> params = std::make_pair(titleSnippet, &found);

        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL
                    {
            char windowTitle[256];
            if (GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle))) {
                // Cast lParam back to our pair pointer
                std::pair<std::string, bool*>* pParams = (std::pair<std::string, bool*>*)lParam;
                
                // Use the RemoteDetector's static helper or just reimplement containsString here since it's a lambda
                // To keep it simple, let's just use strstr or similar, or capture the helper if it was static.
                // Since containsString is a member, we can't call it easily from a static callback without passing 'this'.
                // Let's just do a quick case-insensitive check here.
                std::string wTitle = windowTitle;
                std::string snippet = pParams->first;
                
                auto it = std::search(
                    wTitle.begin(), wTitle.end(),
                    snippet.begin(), snippet.end(),
                    [](char ch1, char ch2) { return std::toupper(ch1) == std::toupper(ch2); }
                );

                if (IsWindowVisible(hwnd) && it != wTitle.end()) {
                    *(pParams->second) = true;
                    return FALSE;
                }
            }
            return TRUE; }, (LPARAM)&params); // Pass address of the named variable

        return found;
    }

public:
    // --- WRAPPER FUNCTIONS ---

    void runPassiveChecks(std::vector<std::string>& passive_threats) {
        for (const auto &rat : ratList) {
            bool isPassive = false;
            
            // Check Service (Installed but stopped)
            ThreatLevel status = checkServiceState(rat.services.empty() ? "" : rat.services[0]); // Check first service for simplicity or iterate all
            // Better to iterate all services in the struct
            for(const auto& s : rat.services) {
                 if (checkServiceState(s) == PASSIVE) isPassive = true;
            }

            if (isPassive) passive_threats.push_back(rat.name + " Service Installed (Stopped)");
            
            if (checkRegistryInstall(rat.name)) passive_threats.push_back(rat.name + " found in Uninstall Registry");
            
            for (const auto &path : rat.installPaths) {
                if (pathExists(path)) passive_threats.push_back(rat.name + " installation folder found");
            }
        }
    }

    void runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score) {
        // 1. RDP Check (Hard)
        if (checkRDPSession()) active_hard.push_back("RDP Session Active");

        // 2. Port Check (Soft)
        size_t initial_soft_count = active_soft.size();
        checkPorts(active_soft);
        size_t new_ports_found = active_soft.size() - initial_soft_count;
        if (new_ports_found > 0) {
            confidence_score += (new_ports_found * 20); // 20 points per suspicious port
        }

        // 3. Tool-Specific Active Checks
        for (const auto &rat : ratList) {
            // Processes (Hard)
            for (const auto &p : rat.processes) {
                if (isProcessRunning(p)) active_hard.push_back(rat.name + " Process Running (" + p + ")");
            }

            // Services (Hard if running)
            for (const auto &s : rat.services) {
                if (checkServiceState(s) == ACTIVE) active_hard.push_back(rat.name + " Service Running (" + s + ")");
            }

            // Window Titles (Soft)
            for (const auto &t : rat.windowTitles) {
                if (windowTitleExists(t)) {
                    active_soft.push_back("Suspicious Window Visible: " + t);
                    confidence_score += 30; // 30 points per suspicious window
                }
            }
        }
    }

private: // Helper methods made private or kept here if needed by others (but main only needs wrappers)
    
    // 7. RDP Session Check
    bool checkRDPSession()
    {
        if (GetSystemMetrics(SM_REMOTESESSION) != 0)
            return true;
        bool isRemote = false;
        DWORD *pBuffer = NULL;
        DWORD bytesReturned = 0;
        if (WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, (WTS_INFO_CLASS)WTSClientProtocolType, (LPSTR *)&pBuffer, &bytesReturned))
        {
            if (bytesReturned > 0 && pBuffer != NULL)
            {
                if (*((unsigned short *)pBuffer) == 2)
                    isRemote = true;
            }
            WTSFreeMemory(pBuffer);
        }
        return isRemote;
    }

    // 6. Port Check
    void checkPorts(std::vector<std::string> &detections)
    {
        PMIB_TCPTABLE pTcpTable;
        ULONG ulSize = 0;

        // Get required size
        if (GetTcpTable(NULL, &ulSize, FALSE) == ERROR_INSUFFICIENT_BUFFER)
        {
            pTcpTable = (PMIB_TCPTABLE)malloc(ulSize);
        }
        else
        {
            return;
        }

        if (GetTcpTable(pTcpTable, &ulSize, FALSE) == NO_ERROR)
        {
            for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++)
            {
                if (pTcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN ||
                    pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB)
                {
                    int port = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
                    for (const auto &rat : ratList)
                    {
                        for (int ratPort : rat.ports)
                        {
                            if (port == ratPort)
                            {
                                detections.push_back("Port " + std::to_string(port) + " (used by " + rat.name + ")");
                            }
                        }
                    }
                }
            }
        }
        free(pTcpTable);
    }

};
