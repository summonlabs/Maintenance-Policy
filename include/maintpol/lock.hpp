#pragma once

#include <memory>
#include <string>

#include "maintpol/error.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// OS level single writer exclusion.
//
// A writer holds an exclusive lock for the lifetime of the store handle. The
// lock file handle is closed by the kernel when the process dies, so a crashed
// writer never leaves a stale lock behind and a live writer can never be
// evaded by a second process.
//
// Read-only inspection deliberately takes no lock: published state is replaced
// atomically, so a reader observes either the previous or the new generation
// and never a partial one.
// ---------------------------------------------------------------------------
class WriterLock {
public:
    WriterLock();
    ~WriterLock();

    WriterLock(const WriterLock&) = delete;
    WriterLock& operator=(const WriterLock&) = delete;
    WriterLock(WriterLock&& other) noexcept;
    WriterLock& operator=(WriterLock&& other) noexcept;

    static Result<WriterLock> acquire_exclusive(const std::string& path);

    bool held() const;
    void release();

private:
    struct Impl;
    static Result<WriterLock> acquire_impl(const std::string& path);

    std::unique_ptr<Impl> impl_;
};

}  // namespace maintpol
