#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstdlib>

void clearScreen()
{
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
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
