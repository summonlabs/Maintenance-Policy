#pragma once

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

#include "maintpol/error.hpp"

namespace maintpol {

// ---------------------------------------------------------------------------
// Time model.
//
// Every instant is an exact UTC point on the proleptic Gregorian timeline,
// stored as signed nanoseconds since 1970-01-01T00:00:00Z. The representable
// range of std::int64_t nanoseconds is:
//
//   1677-09-21T00:12:43.145224192Z  ..  2262-04-11T23:47:16.854775807Z
//
// Civil dates outside 0001-01-01 .. 9999-12-31 are not representable in the
// canonical text form and are rejected. Leap seconds are not represented:
// a second field of 60 is rejected rather than smeared. Named time zones are
// not supported; callers supply an explicit UTC offset, which is applied at
// parse time and discarded (all stored instants are UTC).
// ---------------------------------------------------------------------------
class Instant;

class Duration {
public:
    static constexpr std::uint64_t kMaxNanos = 0x7FFFFFFFFFFFFFFFull;

    Duration() = default;

    static Result<Duration> from_nanos(std::uint64_t nanos);
    static Result<Duration> from_millis(std::uint64_t millis);
    static Result<Duration> from_seconds(std::uint64_t seconds);
    static Result<Duration> from_minutes(std::uint64_t minutes);
    static Result<Duration> from_hours(std::uint64_t hours);
    static Result<Duration> from_days(std::uint64_t days);

    std::uint64_t nanos() const { return nanos_; }
    bool is_zero() const { return nanos_ == 0; }

    // Checked arithmetic: overflow is an error, never a wrapped value.
    Result<Duration> add(const Duration& other) const;
    Result<Duration> multiply(std::uint64_t factor) const;

    static Result<Duration> parse(std::string_view text);
    std::string format() const;

    friend bool operator==(const Duration&, const Duration&) = default;
    friend std::strong_ordering operator<=>(const Duration&, const Duration&) = default;

private:
    std::uint64_t nanos_ = 0;
};

// Signed distance between two instants, in nanoseconds.
class Delta {
public:
    Delta() = default;
    static Delta from_nanos(std::int64_t nanos) { return Delta{nanos}; }
    std::int64_t nanos() const { return nanos_; }
    bool is_negative() const { return nanos_ < 0; }

    friend bool operator==(const Delta&, const Delta&) = default;
    friend std::strong_ordering operator<=>(const Delta&, const Delta&) = default;

private:
    explicit Delta(std::int64_t nanos) : nanos_(nanos) {}
    std::int64_t nanos_ = 0;
};

struct CivilTime {
    int year = 1970;
    unsigned month = 1;
    unsigned day = 1;
    unsigned hour = 0;
    unsigned minute = 0;
    unsigned second = 0;
    std::uint32_t nanosecond = 0;

    friend bool operator==(const CivilTime&, const CivilTime&) = default;
};

class ZoneOffset {
public:
    static constexpr int kMaxMinutes = 18 * 60;

    ZoneOffset() = default;

    static Result<ZoneOffset> from_minutes(int minutes);
    int minutes() const { return minutes_; }

    friend bool operator==(const ZoneOffset&, const ZoneOffset&) = default;

private:
    int minutes_ = 0;
};

class Instant {
public:
    static constexpr std::int64_t kMinNanos = INT64_MIN;
    static constexpr std::int64_t kMaxNanos = INT64_MAX;

    Instant() = default;

    static Result<Instant> from_unix_nanos(std::int64_t nanos);
    static Result<Instant> from_civil(const CivilTime& civil);
    static Result<Instant> from_civil_with_offset(const CivilTime& civil, const ZoneOffset& offset);
    static Result<Instant> parse(std::string_view text);
    // Parses a civil date (YYYY-MM-DD) at 00:00:00 UTC.
    static Result<Instant> parse_date(std::string_view text);

    std::int64_t unix_nanos() const { return nanos_; }

    Result<CivilTime> to_civil() const;
    // Formats as YYYY-MM-DDTHH:MM:SS.fffffffffZ (always nine fractional digits).
    std::string format() const;
    std::string format_date() const;

    Result<Instant> add(const Duration& duration) const;
    Result<Instant> subtract(const Duration& duration) const;
    // Returns an error rather than saturating when the distance is not
    // representable as a signed 64 bit nanosecond count.
    Result<Delta> difference(const Instant& other) const;

    friend bool operator==(const Instant&, const Instant&) = default;
    friend std::strong_ordering operator<=>(const Instant&, const Instant&) = default;

private:
    explicit Instant(std::int64_t nanos) : nanos_(nanos) {}
    std::int64_t nanos_ = 0;
};

// True when the proleptic Gregorian year is a leap year.
MAINTPOL_API bool is_leap_year(int year);
MAINTPOL_API unsigned days_in_month(int year, unsigned month);
// Days since 1970-01-01 for a valid civil date; the caller validates the date.
MAINTPOL_API std::int64_t days_from_civil(int year, unsigned month, unsigned day);
MAINTPOL_API CivilTime civil_from_days(std::int64_t days);
// Formats a signed nanosecond count as an exact duration string.
MAINTPOL_API std::string format_duration_nanos(std::uint64_t nanos);
MAINTPOL_API Result<std::uint64_t> parse_duration_nanos(std::string_view text);

}  // namespace maintpol
