#include "../../include/device_detect.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmath>
#include <chrono>

// Need to handle missing simple types if generic includes aren't enough
// but usually these are standard.

struct POINT_LINUX {
    int x, y;
};

// Monitors check via /sys/class/drm
bool checkMonitorsLinux(std::vector<std::string>& active_hard) {
    int connected_count = 0;
    DIR *d;
    struct dirent *dir;
    d = opendir("/sys/class/drm");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            std::string dname = dir->d_name;
            // Look for cardX-Connector (e.g., card0-HDMI-A-1)
            // Filter out virtual/unknown if necessary, but "connected" usually means physical link
            if (dname.find("card") == 0 && dname.find("-") != std::string::npos) {
                 std::string statusPath = std::string("/sys/class/drm/") + dname + "/status";
                 std::ifstream f(statusPath);
                 if (f.good()) {
                     std::string status;
                     std::getline(f, status);
                     if (status == "connected") {
                         connected_count++;
                     }
                 }
            }
        }
        closedir(d);
    }
    
    if (connected_count > 1) return true;
    return false;
}

// Webcams check via /sys/class/video4linux
void checkWebcamsLinux(std::vector<std::string>& active_soft, int& confidence_score) {
    int cams = 0;
    DIR *d;
    struct dirent *dir;
    d = opendir("/sys/class/video4linux");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            std::string dname = dir->d_name;
            if (dname.find("video") == 0) { // e.g., video0
                std::string namePath = std::string("/sys/class/video4linux/") + dname + "/name";
                std::ifstream f(namePath);
                if (f.good()) {
                    std::string deviceName;
                    std::getline(f, deviceName);
                    
                    // Simple filter for dummy/metadata devices if possible
                    // But counting them is safer for now.
                    // ManyCam/OBS often show up here.
                    if (deviceName.find("OBS") != std::string::npos ||
                        deviceName.find("dummy") != std::string::npos ||
                        deviceName.find("Loopback") != std::string::npos) {
                         active_soft.push_back("Virtual Camera Detected: " + deviceName);
                    }
                    cams++; 
                }
            }
        }
        closedir(d);
    }
    
    // Heuristic: usually 1 video device (webcam) + maybe 1 metadata node.
    // If > 2, likely multiple cams or virtual cams.
    if (cams > 2) {
         active_soft.push_back("Multiple/suspicious Video Devices Detected (" + std::to_string(cams) + ")");
         confidence_score += 10;
    }
}

// Mouse Anomaly Check
// Reading from /dev/input/mice (Unified Mouse Interface)
// Requires Root (sudo)
int checkMouseAnomaliesLinux() {
    static int fd = -1;
    static std::chrono::steady_clock::time_point lastTime;
    static bool firstReading = true;
    
    if (fd == -1) {
        fd = open("/dev/input/mice", O_RDONLY | O_NONBLOCK);
        if (fd == -1) return 0; // Cannot open (permission or no mouse)
    }

    // Read mouse packet (3 bytes: [buttons, dx, dy])
    signed char query[3];
    int bytes = read(fd, query, 3);
    
    if (bytes < 3) return 0; // No movement data available right now

    signed char dx = query[1];
    signed char dy = query[2];
    
    auto now = std::chrono::steady_clock::now();
    
    if (firstReading) {
        lastTime = now;
        firstReading = false;
        return 0;
    }

    double elapsedSeconds = std::chrono::duration<double>(now - lastTime).count();
    lastTime = now; // Reset time for next delta
    
    if (elapsedSeconds < 0.001) return 0; // Too fast to measure reliably

    // Distance calculation logic for relative movement
    double distance = std::sqrt(dx*dx + dy*dy);
    double velocity = distance / elapsedSeconds; 

    // Thresholds (Linux might report raw counts differently than Windows pixels)
    // We'll be conservative. Raw counts usually map to pixels but depend on DPI.
    // > 2000 counts/sec is quite fast. > 10000 is likely instant/bot.
    
    if (velocity > 10000.0) return 2; // Bot-like
    if (velocity > 2000.0) return 1;  // Suspicious fast

    return 0;
}

void DeviceDetector::runPassiveChecks(std::vector<std::string>& passive_threats) {
    // None
}

void DeviceDetector::runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score) {
    if (checkMonitorsLinux(active_hard)) active_hard.push_back("Multiple Monitors Connected");
    
    checkWebcamsLinux(active_soft, confidence_score);
    
    int mouseStatus = checkMouseAnomaliesLinux();
    if (mouseStatus == 2) active_hard.push_back("Mouse Teleportation (Bot)");
    else if (mouseStatus == 1) {
        active_soft.push_back("Suspicious Mouse Speed");
        confidence_score += 20;
    }
}
