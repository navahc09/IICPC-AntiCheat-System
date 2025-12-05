#include "../../include/screen_sharing_detect.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <dirent.h>

std::string toLowerScreen(const std::string &str)
{
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c)
                   { return std::tolower(c); });
    return lower;
}

std::vector<std::string> screenTools = {
    "obs", "discord", "zoom", "teams", "slack", "skype", "webex", "fameshot", "kazam", "simplescreenrecorder"
};

void checkScreenProcesses(std::vector<std::string> &active_hard) {
    DIR *d;
    struct dirent *dir;
    d = opendir("/proc");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (!isdigit(dir->d_name[0])) continue;
            
            std::string pid = dir->d_name;
            std::ifstream cmd(std::string("/proc/") + pid + "/comm");
            if (cmd.good()) {
                std::string name;
                std::getline(cmd, name);
                std::string lowerName = toLowerScreen(name);
                
                for (const auto& tool : screenTools) {
                     if (lowerName.find(tool) != std::string::npos) {
                         active_hard.push_back("Screen Tool Process: " + name);
                     }
                }
            }
        }
        closedir(d);
    }
}

void ScreenShareDetector::runPassiveChecks(std::vector<std::string>& passive_threats) {
    // Check installed
    for (const auto& tool : screenTools) {
         std::string path = "/usr/bin/" + tool;
         std::ifstream f(path);
         if (f.good()) passive_threats.push_back("Screen Tool Installed: " + tool);
    }
}

void ScreenShareDetector::runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score) {
    checkScreenProcesses(active_hard);
    // Window Titles in Linux usually require X11 (Xlib) or Wayland protocols.
    // XLib is complex to header-only or keep simple.
    // For now, process check is the most reliable "headless" check.
}
