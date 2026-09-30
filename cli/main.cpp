#include <string>
#include <vector>

#include "commands.hpp"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>

int wmain(int argc, wchar_t** argv) {
    std::vector<std::string> arguments;
    arguments.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
    for (int index = 1; index < argc; ++index) {
        const wchar_t* wide = argv[index];
        const int size = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
        if (size <= 1) {
            arguments.emplace_back();
            continue;
        }
        std::string narrow(static_cast<std::size_t>(size - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, wide, -1, narrow.data(), size, nullptr, nullptr);
        arguments.push_back(std::move(narrow));
    }
    return maintpol::cli::run(arguments);
}
#else
int main(int argc, char** argv) {
    std::vector<std::string> arguments;
    arguments.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
    for (int index = 1; index < argc; ++index) {
        arguments.emplace_back(argv[index]);
    }
    return maintpol::cli::run(arguments);
}
#endif
