#include "maintpol/error.hpp"

namespace maintpol {
namespace {

struct CodeInfo {
    Code code;
    std::string_view name;
    CodeClass code_class;
    Severity severity;
    std::string_view text;
};

constexpr CodeInfo kCodeTable[] = {
#define MAINTPOL_CODE_INFO(name, value, cls, sev, text) \
    CodeInfo{Code::name, #name, CodeClass::cls, Severity::sev, text},
    MAINTPOL_CODE_TABLE(MAINTPOL_CODE_INFO)
#undef MAINTPOL_CODE_INFO
};

constexpr std::size_t kCodeCount = sizeof(kCodeTable) / sizeof(kCodeTable[0]);

constexpr const CodeInfo* find_info(Code code) {
    for (std::size_t i = 0; i < kCodeCount; ++i) {
        if (kCodeTable[i].code == code) {
            return &kCodeTable[i];
        }
    }
    return nullptr;
}

}  // namespace

std::string_view to_string(Code code) {
    const CodeInfo* info = find_info(code);
    return info != nullptr ? info->name : std::string_view("UnknownCode");
}

std::string_view description(Code code) {
    const CodeInfo* info = find_info(code);
    return info != nullptr ? info->text : std::string_view("unrecognised code");
}

Severity severity_of(Code code) {
    const CodeInfo* info = find_info(code);
    return info != nullptr ? info->severity : Severity::Error;
}

CodeClass class_of(Code code) {
    const CodeInfo* info = find_info(code);
    return info != nullptr ? info->code_class : CodeClass::Internal;
}

std::uint16_t value_of(Code code) { return static_cast<std::uint16_t>(code); }

bool code_from_value(std::uint16_t value, Code& out) {
    for (std::size_t i = 0; i < kCodeCount; ++i) {
        if (static_cast<std::uint16_t>(kCodeTable[i].code) == value) {
            out = kCodeTable[i].code;
            return true;
        }
    }
    return false;
}

bool code_from_name(std::string_view name, Code& out) {
    for (std::size_t i = 0; i < kCodeCount; ++i) {
        if (kCodeTable[i].name == name) {
            out = kCodeTable[i].code;
            return true;
        }
    }
    return false;
}

std::string_view to_string(Severity severity) {
    switch (severity) {
        case Severity::None: return "none";
        case Severity::Info: return "info";
        case Severity::Advisory: return "advisory";
        case Severity::Escalation: return "escalation";
        case Severity::Refusal: return "refusal";
        case Severity::Denial: return "denial";
        case Severity::Error: return "error";
    }
    return "unknown";
}

std::string_view to_string(CodeClass code_class) {
    switch (code_class) {
        case CodeClass::None: return "none";
        case CodeClass::Input: return "input";
        case CodeClass::Time: return "time";
        case CodeClass::Policy: return "policy";
        case CodeClass::Authority: return "authority";
        case CodeClass::PolicyState: return "policy-state";
        case CodeClass::Evidence: return "evidence";
        case CodeClass::Evaluation: return "evaluation";
        case CodeClass::Store: return "store";
        case CodeClass::Internal: return "internal";
    }
    return "unknown";
}

bool severity_from_name(std::string_view name, Severity& out) {
    if (name == "none") { out = Severity::None; return true; }
    if (name == "info") { out = Severity::Info; return true; }
    if (name == "advisory") { out = Severity::Advisory; return true; }
    if (name == "escalation") { out = Severity::Escalation; return true; }
    if (name == "refusal") { out = Severity::Refusal; return true; }
    if (name == "denial") { out = Severity::Denial; return true; }
    if (name == "error") { out = Severity::Error; return true; }
    return false;
}

Error make_error(Code code, std::string detail) { return Error{code, std::move(detail)}; }

std::string to_string(const Error& error) {
    std::string result;
    result.reserve(error.detail.size() + 32);
    result.append(to_string(error.code));
    if (!error.detail.empty()) {
        result.append(": ");
        result.append(error.detail);
    }
    return result;
}

}  // namespace maintpol
