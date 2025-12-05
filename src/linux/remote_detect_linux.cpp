#include "../../include/remote_detect.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <dirent.h>
#include <sstream>

// Helper to lower-case
std::string toLowerRemote(const std::string &str)
{
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c)
                   { return std::tolower(c); });
    return lower;
}

struct LinuxRAT {
    std::string name;
    std::vector<std::string> processNames;
    std::vector<int> ports;
};

std::vector<LinuxRAT> linuxRats = {
    {"TeamViewer", {"teamviewerd", "teamviewer"}, {5938}},
    {"AnyDesk", {"anydesk", "anydesk_svc"}, {7070, 6568}},
    {"VNC", {"Xvnc", "vncserver", "x11vnc"}, {5900, 5800}},
    {"Remmina", {"remmina"}, {}},
    {"Chrome Remote Desktop", {"chrome-remote-desktop-host"}, {}},
    {"Sshd", {"sshd"}, {22}}
};

// Check ports via /proc/net/tcp
void checkPortsLinux(std::vector<std::string>& active_soft, int& confidence_score) {
    std::ifstream f("/proc/net/tcp");
    if (!f.good()) return;
    
    std::string line;
    std::getline(f, line); // header usage
    
    int new_ports = 0;

    while(std::getline(f, line)) {
        std::stringstream ss(line);
        std::string sl, local_addr_hex;
        ss >> sl >> local_addr_hex;
        
        // Extract port
        size_t colon = local_addr_hex.find(':');
        if (colon != std::string::npos) {
            std::string portHex = local_addr_hex.substr(colon + 1);
            int port = std::stoi(portHex, nullptr, 16);
            
            for (const auto& rat : linuxRats) {
                for (int p : rat.ports) {
                    if (port == p) {
                         active_soft.push_back("Suspicious Open Port: " + std::to_string(port) + " (" + rat.name + ")");
                         new_ports++;
                    }
                }
            }
        }
    }
    
    if (new_ports > 0) confidence_score += (new_ports * 20);
}

// Check processes via /proc
void checkProcessesLinux(std::vector<std::string>& active_hard) {
    DIR *d;
    struct dirent *dir;
    d = opendir("/proc");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (!isdigit(dir->d_name[0])) continue; // Skip non-PID
            
            std::string pid = dir->d_name;
            std::ifstream cmd(std::string("/proc/") + pid + "/comm"); // 'comm' is simpler than cmdline for name
            if (cmd.good()) {
                std::string name;
                std::getline(cmd, name);
                std::string lowerName = toLowerRemote(name);
                
                for (const auto& rat : linuxRats) {
                    for (const auto& proc : rat.processNames) {
                         if (lowerName.find(proc) != std::string::npos) {
                             active_hard.push_back("Process Running: " + name + " (" + rat.name + ")");
                         }
                    }
                }
            }
        }
        closedir(d);
    }
}

void RemoteDetector::runPassiveChecks(std::vector<std::string>& passive_threats) {
    // Check for installed binaries in common paths could go here
    // For now, simpler to skip or check /usr/bin existence
    for (const auto& rat : linuxRats) {
        for (const auto& proc : rat.processNames) {
             std::string path = "/usr/bin/" + proc;
             std::ifstream f(path);
             if (f.good()) passive_threats.push_back("Tool Installed: " + rat.name);
        }
    }
}

void RemoteDetector::runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score) {
    checkProcessesLinux(active_hard);
    checkPortsLinux(active_soft, confidence_score);
    
    // RDP on Linux? (xrdp)
    std::ifstream cmd("/proc/net/tcp");
    // Handled by port check mostly.
    
    // SSH Session check using 'who' or 'w' conceptually, but we can check ENV
    if (getenv("SSH_CLIENT") || getenv("SSH_TTY")) {
        active_hard.push_back("Active SSH Session Detected (Environment)");
    }
}
