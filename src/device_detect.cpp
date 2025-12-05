// Device & System Anomaly Detection Tool
// Compile with: g++ -o device_detect.exe device_detect.cpp -luser32 -lgdi32 -static

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <chrono>
#include <thread>

class DeviceDetector
{
private:
    // Mouse Tracking State
    POINT lastPos;
    std::chrono::steady_clock::time_point lastTime;
    bool firstReading = true;

public:
    // --- WRAPPER FUNCTIONS ---
    
    void runPassiveChecks(std::vector<std::string>& passive_threats) {
        // No specific passive checks for devices yet (could check installed drivers for virtual devices here instead of active loop)
    }

    void runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score) {
        // 1. Monitor Check (Hard)
        if (checkMultiMonitor()) active_hard.push_back("Multiple Monitors Connected");

        // 2. Virtual Monitor Check (Soft)
        checkVirtualMonitors(active_soft, confidence_score);

        // 3. Webcam Check (Hard/Soft)
        checkWebcams(active_hard, active_soft, confidence_score);

        // 4. Mouse Check (Hard/Soft)
        int mouseStatus = checkMouseAnomalies();
        if (mouseStatus == 2) active_hard.push_back("Mouse Teleportation (Bot)");
        else if (mouseStatus == 1) {
            active_soft.push_back("Suspicious Mouse Speed");
            confidence_score += 20;
        }
    }

    // --- INDIVIDUAL CHECKS ---

    // 1. Monitor Check (Hard Check)
    // Returns true if > 1 monitor is detected
    bool checkMultiMonitor()
    {
        int monitors = GetSystemMetrics(SM_CMONITORS);
        return (monitors > 1);
    }

    // 2. Virtual Display Adapter Check (Soft Check)
    // Checks for drivers often used by USB monitors or virtual screens (Spacedesk, etc.)
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
                // std::cout << "[DEBUG] Display: " << deviceString << "\n";

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

    // 3. Mouse Movement Anomaly (Soft/Heuristic)
    // Checks for:
    // A. Impossible Speed (Teleportation) - often caused by absolute positioning bots
    // B. Clipping/Jitter - hard to detect reliably without more data, but we can check for extreme velocity
    // Returns: 0 = Clean, 1 = Suspicious (Fast), 2 = Bot (Teleport)
    int checkMouseAnomalies()
    {
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

        // Avoid division by zero if called too fast
        if (elapsedSeconds < 0.001)
            return 0;

        double distance = std::sqrt(std::pow(p.x - lastPos.x, 2) + std::pow(p.y - lastPos.y, 2));
        double velocity = distance / elapsedSeconds; // Pixels per second

        // Update state
        lastPos = p;
        lastTime = now;

        // Thresholds (Calibrated for 1080p screens)
        // Normal fast flick: ~5000-10000 px/s
        // Bot teleport: > 50000 px/s (Instant jump across screen in < 10ms)
        if (velocity > 50000.0)
        {
            return 2; // Bot-like Teleport
        }
        if (velocity > 20000.0)
        {
            return 1; // Suspiciously Fast
        }

        return 0;
    }

    // 4. Webcam Check (Virtual & External)
    // Checks for:
    // A. Virtual Cameras (OBS, ManyCam, etc.) - Hard Cheat
    // B. Multiple Cameras - Warning (Could be using a secondary cam to bypass proctoring)
    void checkWebcams(std::vector<std::string> &active_hard, std::vector<std::string> &active_soft, int& confidence_score)
    {
        // Registry path for Imaging Devices (Cameras/Scanners)
        // Class GUID: {6bdd1fc6-810f-11d0-bec7-08002be2092f}
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
                            // std::cout << "[DEBUG] Found Camera: " << name << "\n";
                            cameraCount++;

                            // Check for Virtual Cameras
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
};
