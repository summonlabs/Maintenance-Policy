#include <iostream>
#include <string>

#include "harness.hpp"

int main(int argc, char** argv) {
    std::string group;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--group" && index + 1 < argc) {
            group = argv[++index];
        }
    }
    if (group.empty()) {
        std::cout << "running all groups\n";
    } else {
        std::cout << "running group: " << group << "\n";
    }
    return maintpol::test::run_all(group);
}
