#define _WIN32_WINNT 0x0601

#include "../../include/screen_sharing_detect.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <map>

struct ScreenToolInfo
{
    std::string name;
    std::vector<std::string> processes;
    std::vector<std::string> windowTitles;
    std::vector<std::string> windowClasses;
};

// Tool Database
std::vector<ScreenToolInfo> toolList = {
    {"OBS Studio", {"obs64.exe", "obs32.exe"}, {"OBS "}, {"Qt5QWindowIcon"}},
    {"Discord", {"discord.exe"}, {"Discord"}, {}}, 
    {"Zoom", {"zoom.exe"}, {"Zoom Meeting", "Zoom Sharing"}, {"ZPUICommonWindow", "ZPPresentationWindow"}},
    {"Microsoft Teams", {"teams.exe", "ms-teams.exe"}, {"Microsoft Teams"}, {}},
    {"Slack", {"slack.exe"}, {"Slack |"}, {}},
    {"Skype", {"skype.exe"}, {"Skype"}, {}},
    {"Google Meet (Browser)", {}, {"Google Meet", "Meet - "}, {}}, 
    {"Cisco Webex", {"atmgr.exe", "ptoneclk.exe", "webexmta.exe"}, {"Cisco Webex"}, {}},
    {"GoToMeeting", {"g2mcomm.exe", "g2mstart.exe"}, {"GoToMeeting"}, {}},
    {"Snipping Tool", {"snippingtool.exe", "snipandsketch.exe"}, {"Snipping Tool", "Snip & Sketch"}, {}},
    {"LightShot", {"lightshot.exe"}, {"Lightshot"}, {}},
    {"Gyazo", {"gyazostation.exe"}, {"Gyazo"}, {}},
    {"ShareX", {"sharex.exe"}, {"ShareX"}, {}},
    {"Bandicam", {"bdcam.exe"}, {"Bandicam"}, {}},
    {"Camtasia", {"camtasia.exe", "camrecorder.exe"}, {"Camtasia"}, {}}};

// Helper Functions
inline bool containsString(const std::string &haystack, const std::string &needle)
{
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char ch1, char ch2)
        { return std::toupper(ch1) == std::toupper(ch2); });
    return (it != haystack.end());
}

void checkProcesses(std::vector<std::string> &detections)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(snap, &pe))
    {
        do
        {
            std::string exeName = pe.szExeFile;
            for (const auto &tool : toolList)
            {
                for (const auto &proc : tool.processes)
                {
                    if (containsString(exeName, proc))
                    {
                        detections.push_back("Process: " + exeName + " (" + tool.name + ")");
                    }
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

void checkWindows(std::vector<std::string> &active_hard, std::vector<std::string> &active_soft, int& confidence_score)
{
    struct CallbackData
    {
        std::vector<std::string> *active_hard;
        std::vector<std::string> *active_soft;
        int* confidence_score;
    };

    CallbackData data = {&active_hard, &active_soft, &confidence_score};

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL
                {
        CallbackData* pData = (CallbackData*)lParam;

        if (!IsWindowVisible(hwnd)) return TRUE;

        char title[256];
        char className[256];
        GetWindowTextA(hwnd, title, sizeof(title));
        GetClassNameA(hwnd, className, sizeof(className));

        std::string sTitle = title;
        std::string sClass = className;

        if (sTitle.empty()) return TRUE;

        for (const auto& tool : toolList) {
            for (const auto& t : tool.windowTitles) {
                if (containsString(sTitle, t)) {
                    pData->active_hard->push_back("Window: '" + sTitle + "' (" + tool.name + ")");
                }
            }
            for (const auto& c : tool.windowClasses) {
                if (sClass == c) {
                    pData->active_hard->push_back("Window Class: " + sClass + " (" + tool.name + ")");
                }
            }
        }

        if (containsString(sTitle, "Stop Sharing") || 
            containsString(sTitle, "is sharing your screen") ||
            containsString(sTitle, "Stop recording")) {
            pData->active_soft->push_back("Suspicious Overlay: '" + sTitle + "'");
            *(pData->confidence_score) += 40; 
        }

        if (sClass == "GDI+ Hook Window Class" || sClass == "ScreenCapture") {
                pData->active_soft->push_back("Suspicious Window Class: " + sClass);
                *(pData->confidence_score) += 30;
        }

        return TRUE; }, (LPARAM)&data);
}

// --- ScreenShareDetector Class Implementation ---

void ScreenShareDetector::runPassiveChecks(std::vector<std::string>& passive_threats) {
    // Currently no passive checks for Screen Sharing
}

void ScreenShareDetector::runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score) {
    checkProcesses(active_hard);
    checkWindows(active_hard, active_soft, confidence_score);
}
