#include "../../include/vm_detect.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <dirent.h>
#include <unistd.h>

// Helper to lower-case strings
std::string toLower(const std::string &str)
{
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c)
                   { return std::tolower(c); });
    return lower;
}

// 1. Check Product Name (DMI)
bool checkDMIProduct() {
    std::ifstream f("/sys/class/dmi/id/product_name");
    if (f.good()) {
        std::string line;
        std::getline(f, line);
        std::string lower = toLower(line);
        if (lower.find("virtualbox") != std::string::npos ||
            lower.find("vmware") != std::string::npos ||
            lower.find("kvm") != std::string::npos ||
            lower.find("qemu") != std::string::npos ||
            lower.find("bochs") != std::string::npos) {
            return true;
        }
    }
    return false;
}

// 2. Check Vendor (DMI)
bool checkDMIVendor() {
    std::ifstream f("/sys/class/dmi/id/sys_vendor");
    if (f.good()) {
        std::string line;
        std::getline(f, line);
        std::string lower = toLower(line);
        if (lower.find("innotek") != std::string::npos || // VirtualBox
            lower.find("vmware") != std::string::npos || 
            lower.find("qemu") != std::string::npos ||
            lower.find("xen") != std::string::npos) {
            return true;
        }
    }
    return false;
}

// 3. CPU Info Check
bool checkCPUInfo() {
    std::ifstream f("/proc/cpuinfo");
    if (f.good()) {
        std::string line;
        while (std::getline(f, line)) {
            if (line.find("hypervisor") != std::string::npos) return true;
            std::string lower = toLower(line);
            if (lower.find("qemu virtual cpu") != std::string::npos) return true;
            if (lower.find("common kvm processor") != std::string::npos) return true;
        }
    }
    return false;
}

// 4. MAC Address Check (OUI) - Reads /sys/class/net/*/address
bool checkMacAddressLinux() {
    DIR *d;
    struct dirent *dir;
    d = opendir("/sys/class/net");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_name[0] == '.') continue;
            std::string path = std::string("/sys/class/net/") + dir->d_name + "/address";
            std::ifstream f(path);
            if (f.good()) {
                std::string mac;
                std::getline(f, mac); // e.g., 00:0c:29:xx:xx:xx
                // Normalize
                mac = toLower(mac);
                if (mac.find("00:05:69") == 0 || mac.find("00:0c:29") == 0 || mac.find("00:50:56") == 0) return true; // VMware
                if (mac.find("08:00:27") == 0) return true; // VirtualBox
                if (mac.find("52:54:00") == 0) return true; // QEMU/KVM
            }
        }
        closedir(d);
    }
    return false;
}

// Implementation

void VMDetector::runPassiveChecks(std::vector<std::string>& passive_threats) {
    if (checkDMIProduct()) passive_threats.push_back("VM Detected (DMI Product Name)");
    if (checkDMIVendor()) passive_threats.push_back("VM Detected (DMI Vendor)");
    if (checkMacAddressLinux()) passive_threats.push_back("Suspicious MAC Address (VM OUI)");
}

void VMDetector::runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score) {
    // Linux active checks are similar but often rely on the same files.
    // Repeating checking /proc/cpuinfo is cheap.
    if (checkCPUInfo()) active_hard.push_back("Critical: Hypervisor CPU Flag / Model Detected");
    
    // We can check for specific modules
    std::ifstream modules("/proc/modules");
    if (modules.good()) {
        std::string line;
        while (std::getline(modules, line)) {
            if (line.find("vboxguest") != std::string::npos || 
                line.find("vmw_ballon") != std::string::npos ||
                line.find("virtio_pci") != std::string::npos) {
                active_hard.push_back("Critical: VM Kernel Module Loaded (" + line.substr(0, line.find(' ')) + ")");
                break; // One is enough
            }
        }
    }
}
