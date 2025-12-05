#ifndef VM_DETECT_HPP
#define VM_DETECT_HPP

#include <vector>
#include <string>

class VMDetector {
public:
    void runPassiveChecks(std::vector<std::string>& passive_threats);
    void runActiveChecks(std::vector<std::string>& active_hard, std::vector<std::string>& active_soft, int& confidence_score);
};

#endif // VM_DETECT_HPP
