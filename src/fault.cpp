#include "maintpol/fault.hpp"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <process.h>
#else
#  include <unistd.h>
#endif

namespace maintpol {

std::string_view to_string(FaultPoint point) {
    switch (point) {
        case FaultPoint::None: return "none";
        case FaultPoint::AfterRecordTempWrite: return "after-record-temp-write";
        case FaultPoint::AfterRecordTempFlush: return "after-record-temp-flush";
        case FaultPoint::AfterRecordTempVerify: return "after-record-temp-verify";
        case FaultPoint::AfterRecordPublish: return "after-record-publish";
        case FaultPoint::AfterManifestTempWrite: return "after-manifest-temp-write";
        case FaultPoint::AfterManifestTempFlush: return "after-manifest-temp-flush";
        case FaultPoint::AfterManifestTempVerify: return "after-manifest-temp-verify";
        case FaultPoint::AfterManifestPublish: return "after-manifest-publish";
        case FaultPoint::AfterFenceAppend: return "after-fence-append";
        case FaultPoint::BeforeJournalFlush: return "before-journal-flush";
        case FaultPoint::AfterJournalFlush: return "after-journal-flush";
    }
    return "none";
}

bool fault_point_from_name(std::string_view name, FaultPoint& out) {
    for (std::uint8_t value = 0; value <= static_cast<std::uint8_t>(FaultPoint::AfterJournalFlush); ++value) {
        const auto point = static_cast<FaultPoint>(value);
        if (to_string(point) == name) {
            out = point;
            return true;
        }
    }
    return false;
}

void terminate_process_now() {
#if defined(_WIN32)
    TerminateProcess(GetCurrentProcess(), 3);
    // TerminateProcess does not return for the calling thread in practice; if
    // it somehow does, fall through to a hard exit.
    _exit(3);
#else
    _exit(3);
#endif
}

void fault_point(const FaultPlan& plan, FaultPoint point) {
    if (plan.crash_at != FaultPoint::None && plan.crash_at == point) {
        terminate_process_now();
    }
}

}  // namespace maintpol
