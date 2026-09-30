#pragma once

#include <string>
#include <vector>

namespace maintpol::cli {

// Exit codes are part of the command line contract:
//   0  success, or a decision that permits the work
//   1  usage, input or storage error
//   2  the decision denies the work
//   3  the decision cannot be resolved (unknown / refusal)
//   4  the decision requires escalation
inline constexpr int kExitOk = 0;
inline constexpr int kExitError = 1;
inline constexpr int kExitDeny = 2;
inline constexpr int kExitUnknown = 3;
inline constexpr int kExitEscalation = 4;

// Runs one command line. Arguments exclude the program name.
int run(const std::vector<std::string>& arguments);

}  // namespace maintpol::cli
