#include "maintpol/fileio.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <system_error>

#include "maintpol/types.hpp"

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
#  include <sys/stat.h>
#  include <unistd.h>
#endif

namespace maintpol {
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

// Long path aware conversion: extended length paths are prefixed so that the
// Win32 layer does not apply MAX_PATH or device-name parsing.
std::wstring native_path(const std::string& path, bool allow_reserved) {
    std::string normalized = path;
    std::replace(normalized.begin(), normalized.end(), '/', '\\');
    const bool absolute = normalized.size() >= 3u && normalized[1] == ':' && normalized[2] == '\\';
    const bool unc = normalized.size() >= 2u && normalized[0] == '\\' && normalized[1] == '\\';
    const bool already_prefix = normalized.compare(0, 4, "\\\\?\\") == 0;
    if (already_prefix) {
        return widen(normalized);
    }
    if (!allow_reserved || normalized.size() > 200u) {
        if (absolute || unc) {
            return widen("\\\\?\\" + normalized);
        }
    }
    return widen(normalized);
}

Result<void> last_error(const std::string& what) {
    const DWORD code = GetLastError();
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), " (win32 error %lu)", static_cast<unsigned long>(code));
    return make_error(Code::StoreIo, what + buffer);
}

#endif

bool is_reserved_device_name(std::string_view component) {
    std::string name(component);
    const std::size_t dot = name.find('.');
    if (dot != std::string::npos) {
        name.resize(dot);
    }
    if (name.empty()) {
        return false;
    }
    for (char& character : name) {
        if (character >= 'A' && character <= 'Z') {
            character = static_cast<char>(character - 'A' + 'a');
        }
    }
    if (name == "con" || name == "prn" || name == "aux" || name == "nul") {
        return true;
    }
    if (name.size() == 4u && (name.compare(0, 3, "com") == 0 || name.compare(0, 3, "lpt") == 0) &&
        name[3] >= '1' && name[3] <= '9') {
        return true;
    }
    return false;
}

bool contains_only_valid_path_characters(std::string_view path) {
    for (char character : path) {
        const auto byte = static_cast<unsigned char>(character);
        if (byte < 0x20u) {
            return false;
        }
        if (character == '<' || character == '>' || character == '"' || character == '|' || character == '?' ||
            character == '*') {
            return false;
        }
    }
    return true;
}

std::filesystem::path to_fs_path(const std::string& path) {
#if defined(_WIN32)
    return std::filesystem::path(native_path(path, true));
#else
    return std::filesystem::path(path);
#endif
}

}  // namespace

bool is_valid_store_file_name(std::string_view name) {
    if (name.empty() || name.size() > 64u) {
        return false;
    }
    if (name.find('/') != std::string_view::npos || name.find('\\') != std::string_view::npos) {
        return false;
    }
    if (name == "." || name == "..") {
        return false;
    }
    for (char character : name) {
        const bool ok = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                        (character >= '0' && character <= '9') || character == '-' || character == '_' ||
                        character == '.';
        if (!ok) {
            return false;
        }
    }
    return !is_reserved_device_name(name);
}

Result<std::string> normalize_root_path(std::string_view path) {
    if (path.empty()) {
        return make_error(Code::StorePathInvalid, "store path must not be empty");
    }
    if (path.size() > 4096u) {
        return make_error(Code::StorePathInvalid, "store path exceeds 4096 characters");
    }
    if (!is_valid_utf8(path)) {
        return make_error(Code::InvalidUtf8, "store path is not valid UTF-8");
    }
    if (!contains_only_valid_path_characters(path)) {
        return make_error(Code::StorePathInvalid, "store path contains an invalid character");
    }
    std::string normalized(path);
    std::replace(normalized.begin(), normalized.end(), '/', '\\');

    // Reject relative paths: the authoritative store must have a stable,
    // absolute location.
    const bool absolute = normalized.size() >= 3u && normalized[1] == ':' &&
                          (normalized[2] == '\\') && ((normalized[0] >= 'A' && normalized[0] <= 'Z') ||
                                                      (normalized[0] >= 'a' && normalized[0] <= 'z'));
    const bool unc = normalized.size() >= 3u && normalized[0] == '\\' && normalized[1] == '\\' &&
                     normalized[2] != '?' && normalized[2] != '.';
    if (!absolute && !unc) {
        return make_error(Code::StorePathInvalid, "store path must be absolute");
    }
    while (normalized.size() > 3u && normalized.back() == '\\') {
        normalized.pop_back();
    }
    std::size_t start = absolute ? 3u : 2u;
    while (start <= normalized.size()) {
        const std::size_t separator = normalized.find('\\', start);
        const std::size_t end = separator == std::string::npos ? normalized.size() : separator;
        const std::string_view component(normalized.data() + start, end - start);
        if (component.empty()) {
            if (separator == std::string::npos) {
                break;
            }
            return make_error(Code::StorePathInvalid, "store path contains an empty component");
        }
        if (component == "." || component == "..") {
            return make_error(Code::StorePathInvalid, "store path must not contain '.' or '..'");
        }
        if (is_reserved_device_name(component)) {
            return make_error(Code::StorePathInvalid,
                              "store path contains a reserved device name component");
        }
        if (separator == std::string::npos) {
            break;
        }
        start = separator + 1u;
    }
    return normalized;
}

Result<bool> file_exists(const std::string& path) {
    std::error_code error;
    const std::filesystem::file_status status = std::filesystem::status(to_fs_path(path), error);
    if (error) {
        if (error == std::errc::no_such_file_or_directory) {
            return false;
        }
        return make_error(Code::StoreIo, "existence check failed: " + error.message());
    }
    return status.type() != std::filesystem::file_type::not_found;
}

Result<bool> directory_exists(const std::string& path) {
    std::error_code error;
    const std::filesystem::file_status status = std::filesystem::status(to_fs_path(path), error);
    if (error) {
        if (error == std::errc::no_such_file_or_directory) {
            return false;
        }
        return make_error(Code::StoreIo, "directory check failed: " + error.message());
    }
    return std::filesystem::is_directory(status);
}

Result<void> create_directory(const std::string& path, bool fail_if_exists) {
    std::error_code error;
    const bool created = std::filesystem::create_directories(to_fs_path(path), error);
    if (error) {
        return make_error(Code::StoreIo, "directory creation failed: " + error.message());
    }
    if (!created && fail_if_exists) {
        auto existing = directory_exists(path);
        if (existing && existing.value()) {
            return make_error(Code::StoreAlreadyExists, "directory already exists: " + path);
        }
    }
    return {};
}

Result<std::vector<std::string>> list_directory_names(const std::string& path) {
    std::error_code error;
    std::vector<std::string> names;
    std::filesystem::directory_iterator iterator(to_fs_path(path), error);
    if (error) {
        return make_error(Code::StoreIo, "directory listing failed: " + error.message());
    }
    for (const std::filesystem::directory_entry& entry : iterator) {
        names.push_back(entry.path().filename().string());
        if (names.size() > 100000u) {
            return make_error(Code::TooManyItems, "directory contains too many entries");
        }
    }
    std::sort(names.begin(), names.end());
    return names;
}

Result<std::uint64_t> file_size(const std::string& path) {
    std::error_code error;
    const auto size = std::filesystem::file_size(to_fs_path(path), error);
    if (error) {
        return make_error(Code::StoreIo, "size query failed: " + error.message());
    }
    return static_cast<std::uint64_t>(size);
}

Result<std::string> read_file_range(const std::string& path, std::uint64_t offset, std::size_t max_bytes) {
#if defined(_WIN32)
    const std::wstring wide = native_path(path, true);
    HANDLE handle = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return last_error("cannot open '" + path + "'").error();
    }
    LARGE_INTEGER position;
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(handle, position, nullptr, FILE_BEGIN)) {
        const Error error = last_error("cannot seek '" + path + "'").error();
        CloseHandle(handle);
        return error;
    }
    // A single read is bounded to one gibibyte so that the Win32 length field
    // can never truncate silently.
    if (max_bytes > (1u << 30)) {
        CloseHandle(handle);
        return make_error(Code::ValueOutOfRange, "read window exceeds one gibibyte");
    }
    std::string buffer;
    buffer.resize(max_bytes);
    DWORD read = 0;
    const bool ok = ReadFile(handle, buffer.data(), static_cast<DWORD>(max_bytes), &read, nullptr) != 0;
    const DWORD code = GetLastError();
    CloseHandle(handle);
    if (!ok && code != ERROR_HANDLE_EOF) {
        return make_error(Code::StoreIo, "read failed: " + path);
    }
    buffer.resize(read);
    return buffer;
#else
    const int descriptor = ::open(path.c_str(), O_RDONLY);
    if (descriptor < 0) {
        return make_error(Code::StoreIo, "cannot open '" + path + "'");
    }
    std::string buffer;
    buffer.resize(max_bytes);
    const ssize_t read = ::pread(descriptor, buffer.data(), max_bytes, static_cast<off_t>(offset));
    ::close(descriptor);
    if (read < 0) {
        return make_error(Code::StoreIo, "read failed: " + path);
    }
    buffer.resize(static_cast<std::size_t>(read));
    return buffer;
#endif
}

Result<std::string> read_file_bounded(const std::string& path, std::size_t max_bytes) {
    auto size = file_size(path);
    if (!size) {
        return size.error();
    }
    if (size.value() > max_bytes) {
        return make_error(Code::StoreRecordTooLarge, "file exceeds the permitted size: " + path);
    }
    auto content = read_file_range(path, 0, static_cast<std::size_t>(size.value()));
    if (!content) {
        return content.error();
    }
    if (content.value().size() != size.value()) {
        return make_error(Code::LengthMismatch, "file changed size while being read: " + path);
    }
    return content;
}

Result<void> write_file_durable(const std::string& path, std::string_view payload) {
#if defined(_WIN32)
    const std::wstring wide = native_path(path, true);
    HANDLE handle = CreateFileW(wide.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return last_error("cannot create '" + path + "'");
    }
    std::size_t written = 0;
    while (written < payload.size()) {
        const std::size_t chunk = (std::min)(payload.size() - written, static_cast<std::size_t>(1u << 20));
        DWORD count = 0;
        if (!WriteFile(handle, payload.data() + written, static_cast<DWORD>(chunk), &count, nullptr)) {
            const Error error = last_error("write failed: " + path).error();
            CloseHandle(handle);
            return error;
        }
        written += count;
    }
    if (!FlushFileBuffers(handle)) {
        const Error error = last_error("flush failed: " + path).error();
        CloseHandle(handle);
        return error;
    }
    CloseHandle(handle);
    return {};
#else
    const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (descriptor < 0) {
        return make_error(Code::StoreIo, "cannot create '" + path + "'");
    }
    std::size_t written = 0;
    while (written < payload.size()) {
        const ssize_t count = ::write(descriptor, payload.data() + written, payload.size() - written);
        if (count <= 0) {
            ::close(descriptor);
            return make_error(Code::StoreIo, "write failed: " + path);
        }
        written += static_cast<std::size_t>(count);
    }
    if (::fsync(descriptor) != 0) {
        ::close(descriptor);
        return make_error(Code::StoreIo, "flush failed: " + path);
    }
    ::close(descriptor);
    return {};
#endif
}

Result<void> append_file_durable(const std::string& path, std::string_view payload) {
#if defined(_WIN32)
    const std::wstring wide = native_path(path, true);
    HANDLE handle = CreateFileW(wide.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return last_error("cannot open for append '" + path + "'");
    }
    std::size_t written = 0;
    while (written < payload.size()) {
        const std::size_t chunk = (std::min)(payload.size() - written, static_cast<std::size_t>(1u << 20));
        DWORD count = 0;
        if (!WriteFile(handle, payload.data() + written, static_cast<DWORD>(chunk), &count, nullptr)) {
            const Error error = last_error("append failed: " + path).error();
            CloseHandle(handle);
            return error;
        }
        written += count;
    }
    if (!FlushFileBuffers(handle)) {
        const Error error = last_error("flush failed: " + path).error();
        CloseHandle(handle);
        return error;
    }
    CloseHandle(handle);
    return {};
#else
    const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (descriptor < 0) {
        return make_error(Code::StoreIo, "cannot open for append '" + path + "'");
    }
    std::size_t written = 0;
    while (written < payload.size()) {
        const ssize_t count = ::write(descriptor, payload.data() + written, payload.size() - written);
        if (count <= 0) {
            ::close(descriptor);
            return make_error(Code::StoreIo, "append failed: " + path);
        }
        written += static_cast<std::size_t>(count);
    }
    if (::fsync(descriptor) != 0) {
        ::close(descriptor);
        return make_error(Code::StoreIo, "flush failed: " + path);
    }
    ::close(descriptor);
    return {};
#endif
}

Result<void> truncate_file(const std::string& path, std::uint64_t size) {
#if defined(_WIN32)
    const std::wstring wide = native_path(path, true);
    HANDLE handle = CreateFileW(wide.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return last_error("cannot open '" + path + "'");
    }
    LARGE_INTEGER position;
    position.QuadPart = static_cast<LONGLONG>(size);
    if (!SetFilePointerEx(handle, position, nullptr, FILE_BEGIN) || !SetEndOfFile(handle)) {
        const Error error = last_error("truncate failed: " + path).error();
        CloseHandle(handle);
        return error;
    }
    FlushFileBuffers(handle);
    CloseHandle(handle);
    return {};
#else
    if (::truncate(path.c_str(), static_cast<off_t>(size)) != 0) {
        return make_error(Code::StoreIo, "truncate failed: " + path);
    }
    return {};
#endif
}

Result<void> replace_file(const std::string& source, const std::string& target) {
#if defined(_WIN32)
    const std::wstring source_wide = native_path(source, true);
    const std::wstring target_wide = native_path(target, true);
    if (!MoveFileExW(source_wide.c_str(), target_wide.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        return last_error("atomic replace failed: " + target);
    }
    return {};
#else
    if (::rename(source.c_str(), target.c_str()) != 0) {
        return make_error(Code::StoreIo, "atomic replace failed: " + target);
    }
    return {};
#endif
}

Result<void> remove_file(const std::string& path) {
    std::error_code error;
    const bool removed = std::filesystem::remove(to_fs_path(path), error);
    if (error) {
        return make_error(Code::StoreIo, "remove failed: " + error.message());
    }
    (void)removed;
    return {};
}

Result<void> remove_tree(const std::string& path) {
    std::error_code error;
    std::filesystem::remove_all(to_fs_path(path), error);
    if (error) {
        return make_error(Code::StoreIo, "recursive remove failed: " + error.message());
    }
    return {};
}

Result<void> flush_directory(const std::string& path) {
#if defined(_WIN32)
    const std::wstring wide = native_path(path, true);
    HANDLE handle = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        // Directory handles are not always available; NTFS metadata ordering is
        // still enforced by the replace operation itself.
        return {};
    }
    FlushFileBuffers(handle);
    CloseHandle(handle);
    return {};
#else
    const int descriptor = ::open(path.c_str(), O_RDONLY);
    if (descriptor < 0) {
        return {};
    }
    ::fsync(descriptor);
    ::close(descriptor);
    return {};
#endif
}

}  // namespace maintpol
