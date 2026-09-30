#include "maintpol/lock.hpp"

#include <utility>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <sys/file.h>
#  include <unistd.h>
#endif

#include "maintpol/fileio.hpp"

namespace maintpol {

struct WriterLock::Impl {
#if defined(_WIN32)
    HANDLE handle = INVALID_HANDLE_VALUE;
#else
    int descriptor = -1;
#endif
};

namespace {

#if defined(_WIN32)

std::wstring widen(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0) {
        return std::wstring();
    }
    std::wstring wide(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), size);
    return wide;
}

}  // namespace

Result<WriterLock> WriterLock::acquire_impl(const std::string& path) {
    auto impl = std::make_unique<WriterLock::Impl>();
    const std::wstring wide = widen(path);
    if (wide.empty()) {
        return make_error(Code::StoreLockUnavailable, "lock path is not encodable");
    }
    // Sharing only read access means a second writer cannot even open the lock
    // file, which is the first layer of single writer exclusion.
    impl->handle = CreateFileW(wide.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (impl->handle == INVALID_HANDLE_VALUE) {
        const DWORD code = GetLastError();
        if (code == ERROR_SHARING_VIOLATION || code == ERROR_LOCK_VIOLATION || code == ERROR_ACCESS_DENIED) {
            return make_error(Code::StoreLocked, "another process holds the store writer lock");
        }
        return make_error(Code::StoreLockUnavailable, "cannot open the store lock file");
    }
    OVERLAPPED overlapped{};
    if (!LockFileEx(impl->handle, LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped)) {
        const DWORD code = GetLastError();
        CloseHandle(impl->handle);
        if (code == ERROR_LOCK_VIOLATION) {
            return make_error(Code::StoreLocked, "another process holds the store writer lock");
        }
        return make_error(Code::StoreLockUnavailable, "cannot lock the store lock file");
    }
    WriterLock lock;
    lock.impl_ = std::move(impl);
    return lock;
}

#else

Result<WriterLock> WriterLock::acquire_impl(const std::string& path) {
    auto impl = std::make_unique<WriterLock::Impl>();
    impl->descriptor = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
    if (impl->descriptor < 0) {
        return make_error(Code::StoreLockUnavailable, "cannot open the store lock file");
    }
    if (::flock(impl->descriptor, LOCK_EX | LOCK_NB) != 0) {
        ::close(impl->descriptor);
        return make_error(Code::StoreLocked, "another process holds the store writer lock");
    }
    WriterLock lock;
    lock.impl_ = std::move(impl);
    return lock;
}

#endif

WriterLock::WriterLock() = default;

WriterLock::~WriterLock() { release(); }

WriterLock::WriterLock(WriterLock&& other) noexcept : impl_(std::move(other.impl_)) {}

WriterLock& WriterLock::operator=(WriterLock&& other) noexcept {
    if (this != &other) {
        release();
        impl_ = std::move(other.impl_);
    }
    return *this;
}

void WriterLock::release() {
    if (!impl_) {
        return;
    }
#if defined(_WIN32)
    if (impl_->handle != INVALID_HANDLE_VALUE) {
        OVERLAPPED overlapped{};
        UnlockFileEx(impl_->handle, 0, 1, 0, &overlapped);
        CloseHandle(impl_->handle);
        impl_->handle = INVALID_HANDLE_VALUE;
    }
#else
    if (impl_->descriptor >= 0) {
        ::flock(impl_->descriptor, LOCK_UN);
        ::close(impl_->descriptor);
        impl_->descriptor = -1;
    }
#endif
    impl_.reset();
}

bool WriterLock::held() const { return impl_ != nullptr; }

Result<WriterLock> WriterLock::acquire_exclusive(const std::string& path) {
    return acquire_impl(path);
}

}  // namespace maintpol
