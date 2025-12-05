// Main Anti-Cheat Orchestrator
// Compile with: g++ -o main.exe main.cpp vm_detect_mingw.cpp remote_detect.cpp screen_sharing_detect.cpp device_detect.cpp -lws2_32 -liphlpapi -lwtsapi32 -luser32 -lgdi32 -static
// Note: You might need to adjust includes or link order depending on MinGW version.

#include "vm_detect_mingw.cpp"
#include "remote_detect.cpp"
#include "screen_sharing_detect.cpp"
#include "device_detect.cpp"
#include <chrono>
#include <iomanip>
#include <sstream>

void clearScreen()
{
    system("cls");
}

void printBanner()
{
    std::cout << "==================================================\n";
    std::cout << "       IICPC ANTI-CHEAT SYSTEM (TRACK 3)          \n";
    std::cout << "==================================================\n";
}

std::string formatDuration(std::chrono::seconds duration) {
    auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
    duration -= hours;
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration);
    duration -= minutes;
    auto seconds = duration;

    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << hours.count() << ":"
       << std::setw(2) << minutes.count() << ":"
       << std::setw(2) << seconds.count();
    return ss.str();
}

int main()
{
    clearScreen();
    printBanner();

    VMDetector vmDetector;
    RemoteDetector remoteDetector;
    ScreenShareDetector screenDetector;
    DeviceDetector deviceDetector;

    std::cout << "[*] Initializing Protection Modules...\n";
    Sleep(1000);

    // --- PHASE 1: PASSIVE SCAN (One-time check at start) ---
    std::cout << "[*] Running Passive System Scan...\n";
    
    std::vector<std::string> passive_threats;

    // VM Passive
    vmDetector.runPassiveChecks(passive_threats);
    // Remote Passive
    remoteDetector.runPassiveChecks(passive_threats);
    // Screen Passive
    screenDetector.runPassiveChecks(passive_threats);
    // Device Passive
    deviceDetector.runPassiveChecks(passive_threats);
    
    if (!passive_threats.empty()) {
        std::cout << "[INFO] Passive Threats Detected:\n";
        for (const auto& t : passive_threats) std::cout << " - " << t << "\n";
        std::cout << "\n";
    }

    // --- PHASE 2: ACTIVE MONITORING LOOP ---
    std::cout << "[*] Starting Active Monitoring Loop. Press Ctrl+C to stop.\n";
    
    // Dynamic Sleep Interval Logic
    int check_interval_ms;
    if (!passive_threats.empty()) {
        check_interval_ms = 10000; // 10 seconds if passive threats found (High Risk)
    } else {
        check_interval_ms = 25000; // 25 seconds if clean (Low Risk)
    }

    auto start_time = std::chrono::steady_clock::now();

    while (true)
    {
        // --- STEP 1: RUN ACTIVE CHECKS ---
        std::vector<std::string> active_threats_hard; // Hard Checks
        std::vector<std::string> active_threats_soft; // Soft Checks (Confidence Score)
        int global_confidence_score = 0;

        // 1. VM Checks
        vmDetector.runActiveChecks(active_threats_hard, active_threats_soft, global_confidence_score);

        // 2. Remote Access Checks
        remoteDetector.runActiveChecks(active_threats_hard, active_threats_soft, global_confidence_score);

        // 3. Screen Sharing Checks
        screenDetector.runActiveChecks(active_threats_hard, active_threats_soft, global_confidence_score);

        // 4. Device Checks
        deviceDetector.runActiveChecks(active_threats_hard, active_threats_soft, global_confidence_score);

        // --- STEP 2: DISPLAY UI ---
        clearScreen();
        printBanner();
        
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time);
        
        std::cout << "Status: MONITORING\n";
        std::cout << "Time Since Active: " << formatDuration(elapsed) << "\n";
        std::cout << "Check Interval: " << (check_interval_ms / 1000) << "s";
        std::cout << "   |   Soft Check Global Confidence Score: " << global_confidence_score << "/100\n\n";

        // --- STEP 3: DISPLAY RESULTS ---
        if (!active_threats_hard.empty()) {
            std::cout << "[!!!] ACTIVE THREATS (HARD CHECK) [!!!]\n";
            for (const auto& t : active_threats_hard) {
                std::cout << " -> " << t << "\n";
            }
            // In a real exam, we might terminate here.
            // return 1; 
        }

        if (!active_threats_soft.empty()) {
            std::cout << "[WARN] ACTIVE THREATS (SOFT CHECK):\n";
            for (const auto& t : active_threats_soft) {
                std::cout << " -> " << t << "\n";
            }
            
            if (global_confidence_score > 50) {
                 std::cout << "\n[WARNING] HIGH THREAT PROBABILITY DETECTED! (Score > 50)\n";
            }
        }

        if (active_threats_hard.empty() && active_threats_soft.empty()) {
            std::cout << "[OK] System appears clean.\n";
        }
        
        if (!passive_threats.empty()) {
             std::cout << "\n[INFO] Passive Threats (Previously Detected):\n";
             for (const auto& t : passive_threats) std::cout << " - " << t << "\n";
        }

        Sleep(check_interval_ms);
    }

    return 0;
}