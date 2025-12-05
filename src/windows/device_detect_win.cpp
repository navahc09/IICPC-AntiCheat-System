#define _WIN32_WINNT 0x0601

#include "../../include/device_detect.hpp"
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <chrono>
#include <thread>

// Internal state structure (PIMPL) or just static globals/members if not strictly pure
// Since the header only exposes methods, we need to maintain state. 
// The original code had members `lastPos`, `lastTime`, `firstReading`.
// We can include them in the .cpp file via a static/global approach OR careful usage since we are implementing a class.
// But the class definition is in the header! The header I wrote didn't have private members.
// This is a common issue when "headerizing".
// The Header defined:
/*
class DeviceDetector {
public:
    void runPassiveChecks(...);
    void runActiveChecks(...);
};
*/
// It did NOT define the private members. This means I cannot simple use `this->lastPos`.
// I must use `static` variables inside the function or file scope variables, or change the header.
// Changing the header is safer, but I want to keep headers clean.
// Given `DeviceDetector` is instantiated once in `main`, static function variables are simplest and sufficient.

bool checkMultiMonitor()
{
    int monitors = GetSystemMetrics(SM_CMONITORS);
    return (monitors > 1);
}

bool checkVirtualMonitors(std::vector<std::string> &active_soft, int& confidence_score)
{
    DISPLAY_DEVICEA dd;
    dd.cb = sizeof(dd);
    DWORD deviceNum = 0;
    bool found = false;

    while (EnumDisplayDevicesA(NULL, deviceNum, &dd, 0))
    {
        if (dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP)
        {
            std::string deviceString = dd.DeviceString;
            if (deviceString.find("Mirage") != std::string::npos ||
                deviceString.find("IddCx") != std::string::npos ||
                deviceString.find("Citrix") != std::string::npos ||
                deviceString.find("Spacedesk") != std::string::npos ||
                deviceString.find("Luminon") != std::string::npos)
            {
                active_soft.push_back("Virtual Display Adapter: " + deviceString);
                confidence_score += 30;
                found = true;
            }
        }
        deviceNum++;
    }
    return found;
}

int checkMouseAnomalies()
{
    static POINT lastPos;
    static std::chrono::steady_clock::time_point lastTime;
    static bool firstReading = true;

    POINT p;
    if (!GetCursorPos(&p))
        return 0;

    if (firstReading)
    {
        lastPos = p;
        lastTime = std::chrono::steady_clock::now();
        firstReading = false;
        return 0;
    }

    auto now = std::chrono::steady_clock::now();
    double elapsedSeconds = std::chrono::duration<double>(now - lastTime).count();

    if (elapsedSeconds < 0.001)
        return 0;

    double distance = std::sqrt(std::pow(p.x - lastPos.x, 2) + std::pow(p.y - lastPos.y, 2));
    double velocity = distance / elapsedSeconds; 

    lastPos = p;
    lastTime = now;

    if (velocity > 50000.0)
    {
        return 2; 
    }
    if (velocity > 20000.0)
    {
        return 1; 
    }

    return 0;
}

void checkWebcams(std::vector<std::string> &active_hard, std::vector<std::string> &active_soft, int& confidence_score)
{
    const char *pPath = "SYSTEM\\CurrentControlSet\\Control\\Class\\{6bdd1fc6-810f-11d0-bec7-08002be2092f}";

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, pPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        DWORD subKeyCount = 0;
        RegQueryInfoKey(hKey, NULL, NULL, NULL, &subKeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

        int cameraCount = 0;

        for (DWORD i = 0; i < subKeyCount; i++)
        {
            char subKeyName[256];
            DWORD subKeyLen = sizeof(subKeyName);
            if (RegEnumKeyExA(hKey, i, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
            {
                HKEY hSubKey;
                std::string fullPath = std::string(pPath) + "\\" + subKeyName;
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS)
                {
                    char driverDesc[256];
                    DWORD dataSize = sizeof(driverDesc);
                    if (RegQueryValueExA(hSubKey, "DriverDesc", NULL, NULL, (LPBYTE)driverDesc, &dataSize) == ERROR_SUCCESS)
                    {
                        std::string name = std::string(driverDesc);
                        cameraCount++;

                        if (name.find("OBS Virtual Camera") != std::string::npos ||
                            name.find("ManyCam") != std::string::npos ||
                            name.find("SplitCam") != std::string::npos ||
                            name.find("Logi Capture") != std::string::npos ||
                            name.find("XSplit") != std::string::npos ||
                            name.find("Snap Camera") != std::string::npos)
                        {
                            active_hard.push_back("Virtual Camera Detected: " + name);
                        }
                    }
                    RegCloseKey(hSubKey);
                }
            }
        }
        RegCloseKey(hKey);

        if (cameraCount > 1)
        {
            active_soft.push_back("Multiple Webcams Detected (" + std::to_string(cameraCount) + ")");
            confidence_score += 15;
        }
    }
}

// --- DeviceDetector Class Implementation ---

void DeviceDetector::runPassiveChecks(std::vector<std::string>& passive_threats) {
    // No specific passive checks
}

void DeviceDetector::runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score) {
    if (checkMultiMonitor()) active_hard.push_back("Multiple Monitors Connected");

    checkVirtualMonitors(active_soft, confidence_score);

    checkWebcams(active_hard, active_soft, confidence_score);

    int mouseStatus = checkMouseAnomalies();
    if (mouseStatus == 2) active_hard.push_back("Mouse Teleportation (Bot)");
    else if (mouseStatus == 1) {
        active_soft.push_back("Suspicious Mouse Speed");
        confidence_score += 20;
    }
}
