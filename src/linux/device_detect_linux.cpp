#include "../../include/device_detect.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <dirent.h>

// Monitors check via /sys/class/drm
bool checkMonitorsLinux(std::vector<std::string>& active_hard) {
    int connected_count = 0;
    DIR *d;
    struct dirent *dir;
    d = opendir("/sys/class/drm");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            std::string dname = dir->d_name;
            // Look for cardX-Connector
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

// Webcams check via /dev/video*
void checkWebcamsLinux(std::vector<std::string>& active_soft, int& confidence_score) {
    int cams = 0;
    DIR *d;
    struct dirent *dir;
    d = opendir("/dev");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            std::string name = dir->d_name;
            if (name.find("video") == 0 && isdigit(name[5])) {
                // Usually video0, video1. Some are metadata.
                // Checking /sys/class/video4linux is cleaner
                cams++;
            }
        }
        closedir(d);
    }
    // Simple heuristic: /dev/video* often includes loopback devices (v4l2loopback often used by OBS)
    // Counting them might be noisy, but multiple video devices is suspicious if user only has 1 cam.
    if (cams > 2) { // 2 is common (index 0 and 1 for metadata sometimes)
         active_soft.push_back("Multiple Video Devices Detected (" + std::to_string(cams) + ")");
         confidence_score += 15;
    }
}

void DeviceDetector::runPassiveChecks(std::vector<std::string>& passive_threats) {
    // None
}

void DeviceDetector::runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score) {
    if (checkMonitorsLinux(active_hard)) active_hard.push_back("Multiple Monitors Connected");
    
    checkWebcamsLinux(active_soft, confidence_score);
    
    // Mouse anomalies: Linux requires reading /dev/input/mice which needs root or group permissions.
    // Hard to implement portable C++ user-mode check without X11.
}
