#ifndef SCREEN_SHARING_DETECT_HPP
#define SCREEN_SHARING_DETECT_HPP

#include <vector>
#include <string>

class ScreenShareDetector {
public:
    void runPassiveChecks(std::vector<std::string>& passive_threats);
    void runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score);
};

#endif // SCREEN_SHARING_DETECT_HPP
