#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "maintpol/error.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// Durable file primitives.
//
// Commit protocol used by the store: write a temporary file, flush it to the
// device, read it back and verify its content and checksum, then atomically
// replace the published name, then flush the directory. Every step is
// observable, and a failure at any step leaves the previously published state
// authoritative.
// ---------------------------------------------------------------------------

// Validates a caller supplied filesystem path: absolute, bounded, no traversal
// component, and no Windows reserved device name in the final component.
MAINTPOL_API Result<std::string> normalize_root_path(std::string_view path);

MAINTPOL_API Result<bool> file_exists(const std::string& path);
MAINTPOL_API Result<bool> directory_exists(const std::string& path);
MAINTPOL_API Result<void> create_directory(const std::string& path, bool fail_if_exists);
MAINTPOL_API Result<std::vector<std::string>> list_directory_names(const std::string& path);
MAINTPOL_API Result<std::uint64_t> file_size(const std::string& path);

// Reads at most max_bytes; a larger file is an error rather than a truncation.
MAINTPOL_API Result<std::string> read_file_bounded(const std::string& path, std::size_t max_bytes);
// Reads a byte range, used to scan append-only journals.
MAINTPOL_API Result<std::string> read_file_range(const std::string& path, std::uint64_t offset,
                                                 std::size_t max_bytes);

// Creates or replaces the file and flushes it to the device before returning.
MAINTPOL_API Result<void> write_file_durable(const std::string& path, std::string_view payload);
// Appends and flushes, used by the append-only fence and decision journals.
MAINTPOL_API Result<void> append_file_durable(const std::string& path, std::string_view payload);
MAINTPOL_API Result<void> truncate_file(const std::string& path, std::uint64_t size);
// Atomically replaces 'target' with 'source'; the target name never observes a
// partially written file.
MAINTPOL_API Result<void> replace_file(const std::string& source, const std::string& target);
MAINTPOL_API Result<void> remove_file(const std::string& path);
// Recursive removal that survives long paths and reserved device names.
MAINTPOL_API Result<void> remove_tree(const std::string& path);
// Best effort directory metadata flush; documented as advisory on Windows.
MAINTPOL_API Result<void> flush_directory(const std::string& path);

MAINTPOL_API bool is_valid_store_file_name(std::string_view name);

}  // namespace maintpol
