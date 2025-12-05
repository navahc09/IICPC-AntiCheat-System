// Screen Sharing & Recording Detection Tool
// Compile with: g++ -o screen_sharing_detect.exe screen_sharing_detect.cpp -luser32 -lgdi32 -static

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <map>

// Threat Levels
enum ScreenThreatLevel
{
    SCREEN_CLEAN = 0,
    SCREEN_SUSPICIOUS, // Heuristic match (e.g., overlay window)
    SCREEN_ACTIVE      // Known tool running (e.g., OBS process)
};

struct ScreenToolInfo
{
    std::string name;
    std::vector<std::string> processes;
    std::vector<std::string> windowTitles;
    std::vector<std::string> windowClasses;
};

class ScreenShareDetector
{
private:
    // Database of Screen Sharing / Recording Tools
    std::vector<ScreenToolInfo> toolList = {
        {"OBS Studio", {"obs64.exe", "obs32.exe"}, {"OBS "}, {"Qt5QWindowIcon"}},
        {"Discord", {"discord.exe"}, {"Discord"}, {}}, // Discord often uses overlay windows
        {"Zoom", {"zoom.exe"}, {"Zoom Meeting", "Zoom Sharing"}, {"ZPUICommonWindow", "ZPPresentationWindow"}},
        {"Microsoft Teams", {"teams.exe", "ms-teams.exe"}, {"Microsoft Teams"}, {}},
        {"Slack", {"slack.exe"}, {"Slack |"}, {}},
        {"Skype", {"skype.exe"}, {"Skype"}, {}},
        {"Google Meet (Browser)", {}, {"Google Meet", "Meet - "}, {}}, // Hard to detect process, rely on title
        {"Cisco Webex", {"atmgr.exe", "ptoneclk.exe", "webexmta.exe"}, {"Cisco Webex"}, {}},
        {"GoToMeeting", {"g2mcomm.exe", "g2mstart.exe"}, {"GoToMeeting"}, {}},
        {"Snipping Tool", {"snippingtool.exe", "snipandsketch.exe"}, {"Snipping Tool", "Snip & Sketch"}, {}},
        {"LightShot", {"lightshot.exe"}, {"Lightshot"}, {}},
        {"Gyazo", {"gyazostation.exe"}, {"Gyazo"}, {}},
        {"ShareX", {"sharex.exe"}, {"ShareX"}, {}},
        {"Bandicam", {"bdcam.exe"}, {"Bandicam"}, {}},
        {"Camtasia", {"camtasia.exe", "camrecorder.exe"}, {"Camtasia"}, {}}};

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

    // Helper: Lowercase string
    std::string toLower(const std::string &str)
    {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c)
                       { return std::tolower(c); });
        return lower;
    }

    // 1. Check Running Processes (Hard Check)
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

    // 2. Check Window Titles & Classes (Hard/Soft Check)
    void checkWindows(std::vector<std::string> &active_hard, std::vector<std::string> &active_soft, int& confidence_score)
    {
        // We need to pass both vectors to the callback, so we use a struct or pair
        struct CallbackData
        {
            ScreenShareDetector *self;
            std::vector<std::string> *active_hard;
            std::vector<std::string> *active_soft;
            int* confidence_score;
        };

        CallbackData data = {this, &active_hard, &active_soft, &confidence_score};

        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL
                    {
            CallbackData* pData = (CallbackData*)lParam;
            ScreenShareDetector* self = pData->self;

            if (!IsWindowVisible(hwnd)) return TRUE;

            char title[256];
            char className[256];
            GetWindowTextA(hwnd, title, sizeof(title));
            GetClassNameA(hwnd, className, sizeof(className));

            std::string sTitle = title;
            std::string sClass = className;

            if (sTitle.empty()) return TRUE;

            // Check against known tools
            for (const auto& tool : self->toolList) {
                // Title Match
                for (const auto& t : tool.windowTitles) {
                    if (self->containsString(sTitle, t)) {
                        pData->active_hard->push_back("Window: '" + sTitle + "' (" + tool.name + ")");
                    }
                }
                // Class Match (More technical, less prone to false positives from random text)
                for (const auto& c : tool.windowClasses) {
                    if (sClass == c) {
                        pData->active_hard->push_back("Window Class: " + sClass + " (" + tool.name + ")");
                    }
                }
            }

            // Heuristic: Detect "Sharing" indicators
            // Many apps add a border or a small window saying "Stop Sharing"
            if (self->containsString(sTitle, "Stop Sharing") || 
                self->containsString(sTitle, "is sharing your screen") ||
                self->containsString(sTitle, "Stop recording")) {
                pData->active_soft->push_back("Suspicious Overlay: '" + sTitle + "'");
                *(pData->confidence_score) += 40; // High confidence (Overlay usually means active sharing)
            }

            // Heuristic: Detect specific overlay classes often used by screen capture
            if (sClass == "GDI+ Hook Window Class" || sClass == "ScreenCapture") {
                 pData->active_soft->push_back("Suspicious Window Class: " + sClass);
                 *(pData->confidence_score) += 30;
            }

            return TRUE; }, (LPARAM)&data);
    }

    // 3. Magnification API Check (Often used for screen scraping/zooming)
    // This is a bit advanced and might flag accessibility tools, so we treat it as heuristic.
    bool checkMagnification()
    {
        // This is a placeholder. Real detection of Mag API usage usually requires hooking or checking loaded DLLs (Magnification.dll) in other processes.
        // For a standalone scanner, checking if "Magnify.exe" is running is the simple version.
        return false;
    }

public:
    // --- WRAPPER FUNCTIONS ---
    
    void runPassiveChecks(std::vector<std::string>& passive_threats) {
        // Currently no passive checks for Screen Sharing (could add file checks later)
    }

    void runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score) {
        checkProcesses(active_hard);
        checkWindows(active_hard, active_soft, confidence_score);
    }
};
