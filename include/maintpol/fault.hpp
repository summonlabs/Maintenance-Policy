#pragma once

#include <cstdint>
#include <string_view>

#include "maintpol/error.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// Fault injection for durability validation.
//
// Every durable commit is a sequence of observable stages. A fault plan names
// the stage at which the process must terminate abruptly, which is how crash
// consistency is proven: the store is reopened after the kill and must either
// present the previous authoritative generation or fail closed, never a
// half-published state.
//
// This is a real fault: the process is terminated by the kernel
// (TerminateProcess on Windows, _exit elsewhere) at the named stage. It does
// not simulate power loss, so operating system file cache contents survive;
// torn and corrupted on-disk states are additionally exercised by direct
// corruption sweeps in the test suite.
// ---------------------------------------------------------------------------
enum class FaultPoint : std::uint8_t {
    None = 0,
    AfterRecordTempWrite,
    AfterRecordTempFlush,
    AfterRecordTempVerify,
    AfterRecordPublish,
    AfterManifestTempWrite,
    AfterManifestTempFlush,
    AfterManifestTempVerify,
    AfterManifestPublish,
    AfterFenceAppend,
    BeforeJournalFlush,
    AfterJournalFlush,
};

MAINTPOL_API std::string_view to_string(FaultPoint point);
MAINTPOL_API bool fault_point_from_name(std::string_view name, FaultPoint& out);

struct FaultPlan {
    FaultPoint crash_at = FaultPoint::None;
};

// Terminates the process immediately when the current stage matches the plan.
MAINTPOL_API void fault_point(const FaultPlan& plan, FaultPoint point);
MAINTPOL_API void terminate_process_now();  // never returns

}  // namespace maintpol
