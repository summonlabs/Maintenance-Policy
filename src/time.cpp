#include "maintpol/time.hpp"

#include <array>
#include <cstdio>
#include <limits>

namespace maintpol {
namespace {

constexpr std::int64_t kNanosPerSecond = 1000000000;
constexpr std::int64_t kNanosPerMinute = 60 * kNanosPerSecond;
constexpr std::int64_t kNanosPerHour = 60 * kNanosPerMinute;
constexpr std::int64_t kNanosPerDay = 24 * kNanosPerHour;

bool checked_add_i64(std::int64_t left, std::int64_t right, std::int64_t& out) {
    if (right > 0 && left > (std::numeric_limits<std::int64_t>::max)() - right) {
        return false;
    }
    if (right < 0 && left < (std::numeric_limits<std::int64_t>::min)() - right) {
        return false;
    }
    out = left + right;
    return true;
}

bool checked_mul_u64(std::uint64_t left, std::uint64_t right, std::uint64_t& out) {
    if (left != 0 && right > (std::numeric_limits<std::uint64_t>::max)() / left) {
        return false;
    }
    out = left * right;
    return true;
}

bool checked_add_u64(std::uint64_t left, std::uint64_t right, std::uint64_t& out) {
    if (left > (std::numeric_limits<std::uint64_t>::max)() - right) {
        return false;
    }
    out = left + right;
    return true;
}

bool checked_mul_i64(std::int64_t left, std::int64_t right, std::int64_t& out) {
    if (left == 0 || right == 0) {
        out = 0;
        return true;
    }
    // Magnitudes are formed in unsigned arithmetic so that no signed overflow
    // can occur, not even for the minimum representable value.
    const bool negative = (left < 0) != (right < 0);
    const std::uint64_t left_magnitude =
        left < 0 ? (0ull - static_cast<std::uint64_t>(left)) : static_cast<std::uint64_t>(left);
    const std::uint64_t right_magnitude =
        right < 0 ? (0ull - static_cast<std::uint64_t>(right)) : static_cast<std::uint64_t>(right);
    const std::uint64_t limit = negative ? (1ull << 63u) : ((1ull << 63u) - 1ull);
    if (right_magnitude > limit / left_magnitude) {
        return false;
    }
    const std::uint64_t magnitude = left_magnitude * right_magnitude;
    out = negative ? static_cast<std::int64_t>(0ull - magnitude) : static_cast<std::int64_t>(magnitude);
    return true;
}

bool parse_uint(std::string_view text, unsigned digits, std::uint64_t& out) {
    if (text.size() != digits) {
        return false;
    }
    std::uint64_t value = 0;
    for (char character : text) {
        if (character < '0' || character > '9') {
            return false;
        }
        value = (value * 10u) + static_cast<std::uint64_t>(character - '0');
    }
    out = value;
    return true;
}

void append_two_digits(std::string& out, unsigned value) {
    out.push_back(static_cast<char>('0' + ((value / 10u) % 10u)));
    out.push_back(static_cast<char>('0' + (value % 10u)));
}

void append_four_digits(std::string& out, int value) {
    out.push_back(static_cast<char>('0' + ((value / 1000) % 10)));
    out.push_back(static_cast<char>('0' + ((value / 100) % 10)));
    out.push_back(static_cast<char>('0' + ((value / 10) % 10)));
    out.push_back(static_cast<char>('0' + (value % 10)));
}

Result<void> validate_civil(const CivilTime& civil) {
    if (civil.year < 1 || civil.year > 9999) {
        return make_error(Code::CalendarInvalid, "year must be between 0001 and 9999");
    }
    if (civil.month < 1 || civil.month > 12) {
        return make_error(Code::CalendarInvalid, "month must be between 1 and 12");
    }
    const unsigned limit = days_in_month(civil.year, civil.month);
    if (civil.day < 1 || civil.day > limit) {
        return make_error(Code::CalendarInvalid, "day does not exist in this month");
    }
    if (civil.hour > 23) {
        return make_error(Code::CalendarInvalid, "hour must be between 0 and 23");
    }
    if (civil.minute > 59) {
        return make_error(Code::CalendarInvalid, "minute must be between 0 and 59");
    }
    if (civil.second > 59) {
        return make_error(Code::LeapSecondUnsupported, "second must be between 0 and 59");
    }
    if (civil.nanosecond > 999999999u) {
        return make_error(Code::CalendarInvalid, "nanosecond must be below 1000000000");
    }
    return {};
}

}  // namespace

bool is_leap_year(int year) { return ((year % 4) == 0 && (year % 100) != 0) || ((year % 400) == 0); }

unsigned days_in_month(int year, unsigned month) {
    static constexpr std::array<unsigned, 12> kDays = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month < 1 || month > 12) {
        return 0;
    }
    if (month == 2 && is_leap_year(year)) {
        return 29;
    }
    return kDays[month - 1u];
}

std::int64_t days_from_civil(int year, unsigned month, unsigned day) {
    const std::int64_t y = static_cast<std::int64_t>(year) - (month <= 2 ? 1 : 0);
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const std::int64_t year_of_era = y - (era * 400);
    const std::int64_t month_prime =
        month > 2 ? static_cast<std::int64_t>(month) - 3 : static_cast<std::int64_t>(month) + 9;
    const std::int64_t day_of_year = (((153 * month_prime) + 2) / 5) + static_cast<std::int64_t>(day) - 1;
    const std::int64_t day_of_era = (year_of_era * 365) + (year_of_era / 4) - (year_of_era / 100) + day_of_year;
    return (era * 146097) + day_of_era - 719468;
}

CivilTime civil_from_days(std::int64_t days) {
    std::int64_t z = days + 719468;
    const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const std::int64_t day_of_era = z - (era * 146097);
    const std::int64_t year_of_era =
        (day_of_era - (day_of_era / 1460) + (day_of_era / 36524) - (day_of_era / 146096)) / 365;
    const std::int64_t y = year_of_era + (era * 400);
    const std::int64_t day_of_year = day_of_era - ((365 * year_of_era) + (year_of_era / 4) - (year_of_era / 100));
    const std::int64_t month_prime = ((5 * day_of_year) + 2) / 153;
    const std::int64_t day = day_of_year - (((153 * month_prime) + 2) / 5) + 1;
    const std::int64_t month = month_prime + (month_prime < 10 ? 3 : -9);

    CivilTime civil;
    civil.year = static_cast<int>(y + (month <= 2 ? 1 : 0));
    civil.month = static_cast<unsigned>(month);
    civil.day = static_cast<unsigned>(day);
    return civil;
}

Result<Duration> Duration::from_nanos(std::uint64_t nanos) {
    if (nanos > kMaxNanos) {
        return make_error(Code::DurationTooLong, "duration exceeds the maximum representable value");
    }
    Duration duration;
    duration.nanos_ = nanos;
    return duration;
}

Result<Duration> Duration::from_millis(std::uint64_t millis) {
    std::uint64_t nanos = 0;
    if (!checked_mul_u64(millis, 1000000u, nanos)) {
        return make_error(Code::IntegerOverflow, "millisecond duration overflows nanoseconds");
    }
    return from_nanos(nanos);
}

Result<Duration> Duration::from_seconds(std::uint64_t seconds) {
    std::uint64_t nanos = 0;
    if (!checked_mul_u64(seconds, static_cast<std::uint64_t>(kNanosPerSecond), nanos)) {
        return make_error(Code::IntegerOverflow, "second duration overflows nanoseconds");
    }
    return from_nanos(nanos);
}

Result<Duration> Duration::from_minutes(std::uint64_t minutes) {
    std::uint64_t nanos = 0;
    if (!checked_mul_u64(minutes, static_cast<std::uint64_t>(kNanosPerMinute), nanos)) {
        return make_error(Code::IntegerOverflow, "minute duration overflows nanoseconds");
    }
    return from_nanos(nanos);
}

Result<Duration> Duration::from_hours(std::uint64_t hours) {
    std::uint64_t nanos = 0;
    if (!checked_mul_u64(hours, static_cast<std::uint64_t>(kNanosPerHour), nanos)) {
        return make_error(Code::IntegerOverflow, "hour duration overflows nanoseconds");
    }
    return from_nanos(nanos);
}

Result<Duration> Duration::from_days(std::uint64_t days) {
    std::uint64_t nanos = 0;
    if (!checked_mul_u64(days, static_cast<std::uint64_t>(kNanosPerDay), nanos)) {
        return make_error(Code::IntegerOverflow, "day duration overflows nanoseconds");
    }
    return from_nanos(nanos);
}

Result<Duration> Duration::add(const Duration& other) const {
    std::uint64_t sum = 0;
    if (nanos_ > kMaxNanos - other.nanos_) {
        return make_error(Code::IntegerOverflow, "duration addition overflows");
    }
    sum = nanos_ + other.nanos_;
    return from_nanos(sum);
}

Result<Duration> Duration::multiply(std::uint64_t factor) const {
    std::uint64_t product = 0;
    if (!checked_mul_u64(nanos_, factor, product)) {
        return make_error(Code::IntegerOverflow, "duration multiplication overflows");
    }
    return from_nanos(product);
}

std::string format_duration_nanos(std::uint64_t nanos) {
    std::string out;
    out.reserve(32);
    out.push_back('P');
    const std::uint64_t days = nanos / static_cast<std::uint64_t>(kNanosPerDay);
    std::uint64_t remainder = nanos % static_cast<std::uint64_t>(kNanosPerDay);
    if (days > 0) {
        out.append(std::to_string(days));
        out.push_back('D');
    }
    out.push_back('T');
    const std::uint64_t hours = remainder / static_cast<std::uint64_t>(kNanosPerHour);
    remainder %= static_cast<std::uint64_t>(kNanosPerHour);
    const std::uint64_t minutes = remainder / static_cast<std::uint64_t>(kNanosPerMinute);
    remainder %= static_cast<std::uint64_t>(kNanosPerMinute);
    const std::uint64_t seconds = remainder / static_cast<std::uint64_t>(kNanosPerSecond);
    const std::uint64_t fraction = remainder % static_cast<std::uint64_t>(kNanosPerSecond);

    out.append(std::to_string(hours));
    out.push_back('H');
    out.append(std::to_string(minutes));
    out.push_back('M');
    if (fraction == 0) {
        out.append(std::to_string(seconds));
    } else {
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "%llu.%09llu", static_cast<unsigned long long>(seconds),
                      static_cast<unsigned long long>(fraction));
        out.append(buffer);
    }
    out.push_back('S');
    return out;
}

Result<std::uint64_t> parse_duration_nanos(std::string_view text) {
    if (text.empty() || text.size() > 64) {
        return make_error(Code::ValueMalformed, "duration must be a bounded ISO 8601 duration");
    }
    std::size_t index = 0;
    if (text[index] != 'P') {
        return make_error(Code::ValueMalformed, "duration must start with 'P'");
    }
    ++index;

    std::uint64_t total = 0;
    bool in_time = false;
    bool saw_component = false;
    int last_rank = -1;

    while (index < text.size()) {
        if (text[index] == 'T') {
            if (in_time) {
                return make_error(Code::ValueMalformed, "duration declares the time part twice");
            }
            in_time = true;
            ++index;
            continue;
        }
        if (text[index] < '0' || text[index] > '9') {
            return make_error(Code::ValueMalformed, "duration component must start with a digit");
        }
        std::uint64_t value = 0;
        while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
            const std::uint64_t digit = static_cast<std::uint64_t>(text[index] - '0');
            if (!checked_mul_u64(value, 10u, value)) {
                return make_error(Code::IntegerOverflow, "duration component overflows");
            }
            std::uint64_t next = 0;
            if (!checked_add_u64(value, digit, next)) {
                return make_error(Code::IntegerOverflow, "duration component overflows");
            }
            value = next;
            ++index;
        }
        std::uint64_t fraction = 0;
        std::uint32_t fraction_digits = 0;
        if (in_time && index < text.size() && text[index] == '.') {
            ++index;
            while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
                if (fraction_digits < 9u) {
                    fraction = (fraction * 10u) + static_cast<std::uint64_t>(text[index] - '0');
                    ++fraction_digits;
                }
                ++index;
            }
            if (fraction_digits == 0u) {
                return make_error(Code::ValueMalformed, "duration fraction has no digits");
            }
            while (fraction_digits < 9u) {
                fraction *= 10u;
                ++fraction_digits;
            }
        }
        if (index >= text.size()) {
            return make_error(Code::ValueMalformed, "duration component has no unit");
        }
        (void)0;
        const char unit = text[index];
        ++index;
        int rank = -1;
        if (unit == 'D') {
            rank = 0;
        } else if (unit == 'H') {
            rank = 1;
        } else if (unit == 'M') {
            rank = 2;
        } else if (unit == 'S') {
            rank = 3;
        }
        if (rank < 0 || rank <= last_rank) {
            return make_error(Code::ValueMalformed, "duration units must appear once, in descending order");
        }
        last_rank = rank;
        std::uint64_t component = 0;
        if (unit == 'D') {
            if (in_time) {
                return make_error(Code::ValueMalformed, "day component must precede the time part");
            }
            std::uint64_t scaled = 0;
            if (!checked_mul_u64(value, static_cast<std::uint64_t>(kNanosPerDay), scaled)) {
                return make_error(Code::IntegerOverflow, "day component overflows");
            }
            component = scaled;
        } else if (unit == 'H' && in_time) {
            std::uint64_t scaled = 0;
            if (!checked_mul_u64(value, static_cast<std::uint64_t>(kNanosPerHour), scaled)) {
                return make_error(Code::IntegerOverflow, "hour component overflows");
            }
            component = scaled;
        } else if (unit == 'M' && in_time) {
            std::uint64_t scaled = 0;
            if (!checked_mul_u64(value, static_cast<std::uint64_t>(kNanosPerMinute), scaled)) {
                return make_error(Code::IntegerOverflow, "minute component overflows");
            }
            component = scaled;
        } else if (unit == 'S' && in_time) {
            std::uint64_t scaled = 0;
            if (!checked_mul_u64(value, static_cast<std::uint64_t>(kNanosPerSecond), scaled)) {
                return make_error(Code::IntegerOverflow, "second component overflows");
            }
            component = scaled;
            std::uint64_t with_fraction = 0;
            if (component > Duration::kMaxNanos - fraction) {
                return make_error(Code::IntegerOverflow, "second component overflows");
            }
            with_fraction = component + fraction;
            component = with_fraction;
        } else {
            return make_error(Code::ValueMalformed, "duration unit is not recognised or is out of order");
        }
        if (total > Duration::kMaxNanos - component) {
            return make_error(Code::DurationTooLong, "duration exceeds the maximum representable value");
        }
        total += component;
        saw_component = true;
    }

    if (!saw_component) {
        return make_error(Code::ValueMalformed, "duration declares no components");
    }
    return total;
}

Result<Duration> Duration::parse(std::string_view text) {
    auto parsed = parse_duration_nanos(text);
    if (!parsed) {
        return parsed.error();
    }
    return from_nanos(parsed.value());
}

std::string Duration::format() const { return format_duration_nanos(nanos_); }

Result<ZoneOffset> ZoneOffset::from_minutes(int minutes) {
    if (minutes < -kMaxMinutes || minutes > kMaxMinutes) {
        return make_error(Code::OffsetOutOfRange, "UTC offset must be within -18:00..+18:00");
    }
    ZoneOffset offset;
    offset.minutes_ = minutes;
    return offset;
}

Result<Instant> Instant::from_unix_nanos(std::int64_t nanos) {
    Instant candidate{nanos};
    // Reject anything the canonical civil form cannot represent, so that a
    // value which exists in memory is always serialisable exactly.
    auto civil = candidate.to_civil();
    if (!civil) {
        return civil.error();
    }
    return candidate;
}

Result<Instant> Instant::from_civil(const CivilTime& civil) {
    auto valid = validate_civil(civil);
    if (!valid) {
        return valid.error();
    }
    const std::int64_t days = days_from_civil(civil.year, civil.month, civil.day);
    const std::int64_t time_of_day = (static_cast<std::int64_t>(civil.hour) * kNanosPerHour) +
                                     (static_cast<std::int64_t>(civil.minute) * kNanosPerMinute) +
                                     (static_cast<std::int64_t>(civil.second) * kNanosPerSecond) +
                                     static_cast<std::int64_t>(civil.nanosecond);
    std::int64_t total = 0;
    std::int64_t day_nanos = 0;
    if (checked_mul_i64(days, kNanosPerDay, day_nanos)) {
        if (!checked_add_i64(day_nanos, time_of_day, total)) {
            return make_error(Code::TimestampOutOfRange, "civil time is outside the supported instant range");
        }
    } else {
        // The whole day count alone is out of range, which can only happen
        // immediately below the minimum instant. One day is brought back into
        // range, the time of day is subtracted from it, and the two steps are
        // checked separately, so no intermediate value ever overflows.
        if (days >= 0 || time_of_day <= 0) {
            return make_error(Code::TimestampOutOfRange, "civil date is outside the supported instant range");
        }
        std::int64_t shifted_days = 0;
        if (!checked_add_i64(days, 1, shifted_days)) {
            return make_error(Code::TimestampOutOfRange, "civil date is outside the supported instant range");
        }
        std::int64_t shifted_nanos = 0;
        if (!checked_mul_i64(shifted_days, kNanosPerDay, shifted_nanos)) {
            return make_error(Code::TimestampOutOfRange, "civil date is outside the supported instant range");
        }
        const std::int64_t deficit = kNanosPerDay - time_of_day;
        if (!checked_add_i64(shifted_nanos, -deficit, total)) {
            return make_error(Code::TimestampOutOfRange, "civil time is outside the supported instant range");
        }
    }
    return from_unix_nanos(total);
}

Result<Instant> Instant::from_civil_with_offset(const CivilTime& civil, const ZoneOffset& offset) {
    auto utc = from_civil(civil);
    if (!utc) {
        return utc.error();
    }
    const std::int64_t shift = static_cast<std::int64_t>(offset.minutes()) * kNanosPerMinute;
    std::int64_t adjusted = 0;
    if (!checked_add_i64(utc.value().unix_nanos(), -shift, adjusted)) {
        return make_error(Code::TimestampOutOfRange, "UTC offset shifted the instant out of range");
    }
    return from_unix_nanos(adjusted);
}

Result<Instant> Instant::parse(std::string_view text) {
    if (text.size() < 20) {
        return make_error(Code::TimestampMalformed, "timestamp must be at least YYYY-MM-DDTHH:MM:SSZ");
    }
    if (text.size() > 40) {
        return make_error(Code::TimestampMalformed, "timestamp is too long");
    }
    if (text[4] != '-' || text[7] != '-') {
        return make_error(Code::TimestampMalformed, "timestamp must use YYYY-MM-DD separators");
    }
    if (text[10] != 'T' && text[10] != 't') {
        return make_error(Code::TimestampMalformed, "timestamp must separate date and time with 'T'");
    }
    if (text[13] != ':' || text[16] != ':') {
        return make_error(Code::TimestampMalformed, "timestamp must use HH:MM:SS separators");
    }

    std::uint64_t year = 0;
    std::uint64_t month = 0;
    std::uint64_t day = 0;
    std::uint64_t hour = 0;
    std::uint64_t minute = 0;
    std::uint64_t second = 0;
    if (!parse_uint(text.substr(0, 4), 4, year) || !parse_uint(text.substr(5, 2), 2, month) ||
        !parse_uint(text.substr(8, 2), 2, day) || !parse_uint(text.substr(11, 2), 2, hour) ||
        !parse_uint(text.substr(14, 2), 2, minute) || !parse_uint(text.substr(17, 2), 2, second)) {
        return make_error(Code::TimestampMalformed, "timestamp contains a non-digit field");
    }
    if (year == 0) {
        return make_error(Code::CalendarInvalid, "year 0000 is not a valid civil year");
    }

    std::size_t index = 19;
    std::uint64_t fraction = 0;
    unsigned fraction_digits = 0;
    if (index < text.size() && text[index] == '.') {
        ++index;
        while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
            if (fraction_digits < 9u) {
                fraction = (fraction * 10u) + static_cast<std::uint64_t>(text[index] - '0');
                ++fraction_digits;
            } else {
                return make_error(Code::TimestampMalformed, "timestamp fraction exceeds nine digits");
            }
            ++index;
        }
        if (fraction_digits == 0u) {
            return make_error(Code::TimestampMalformed, "timestamp fraction has no digits");
        }
        while (fraction_digits < 9u) {
            fraction *= 10u;
            ++fraction_digits;
        }
    }
    if (index >= text.size()) {
        return make_error(Code::TimestampMalformed, "timestamp has no UTC designator");
    }

    int offset_minutes = 0;
    const char designator = text[index];
    if (designator == 'Z' || designator == 'z') {
        ++index;
        if (index != text.size()) {
            return make_error(Code::TimestampMalformed, "timestamp has trailing characters");
        }
    } else if (designator == '+' || designator == '-') {
        if (text.size() - index != 6 || text[index + 3] != ':') {
            return make_error(Code::TimestampMalformed, "UTC offset must be formatted as +HH:MM or -HH:MM");
        }
        std::uint64_t offset_hours = 0;
        std::uint64_t offset_minutes_part = 0;
        if (!parse_uint(text.substr(index + 1, 2), 2, offset_hours) ||
            !parse_uint(text.substr(index + 4, 2), 2, offset_minutes_part)) {
            return make_error(Code::TimestampMalformed, "UTC offset contains a non-digit field");
        }
        if (offset_minutes_part > 59u) {
            return make_error(Code::OffsetOutOfRange, "UTC offset minutes must be below 60");
        }
        const std::uint64_t total_minutes = (offset_hours * 60u) + offset_minutes_part;
        if (total_minutes > static_cast<std::uint64_t>(ZoneOffset::kMaxMinutes)) {
            return make_error(Code::OffsetOutOfRange, "UTC offset must be within -18:00..+18:00");
        }
        offset_minutes = static_cast<int>(total_minutes);
        if (designator == '-') {
            offset_minutes = -offset_minutes;
        }
    } else {
        return make_error(Code::TimeZoneNotSupported,
                          "timestamp must end with 'Z' or an explicit numeric UTC offset");
    }

    CivilTime civil;
    civil.year = static_cast<int>(year);
    civil.month = static_cast<unsigned>(month);
    civil.day = static_cast<unsigned>(day);
    civil.hour = static_cast<unsigned>(hour);
    civil.minute = static_cast<unsigned>(minute);
    civil.second = static_cast<unsigned>(second);
    civil.nanosecond = static_cast<std::uint32_t>(fraction);

    auto offset = ZoneOffset::from_minutes(offset_minutes);
    if (!offset) {
        return offset.error();
    }
    return from_civil_with_offset(civil, offset.value());
}

Result<Instant> Instant::parse_date(std::string_view text) {
    if (text.size() != 10 || text[4] != '-' || text[7] != '-') {
        return make_error(Code::CalendarInvalid, "civil date must be formatted as YYYY-MM-DD");
    }
    std::uint64_t year = 0;
    std::uint64_t month = 0;
    std::uint64_t day = 0;
    if (!parse_uint(text.substr(0, 4), 4, year) || !parse_uint(text.substr(5, 2), 2, month) ||
        !parse_uint(text.substr(8, 2), 2, day)) {
        return make_error(Code::CalendarInvalid, "civil date contains a non-digit field");
    }
    if (year == 0) {
        return make_error(Code::CalendarInvalid, "year 0000 is not a valid civil year");
    }
    CivilTime civil;
    civil.year = static_cast<int>(year);
    civil.month = static_cast<unsigned>(month);
    civil.day = static_cast<unsigned>(day);
    return from_civil(civil);
}

Result<CivilTime> Instant::to_civil() const {
    std::int64_t days = nanos_ / kNanosPerDay;
    std::int64_t remainder = nanos_ % kNanosPerDay;
    if (remainder < 0) {
        remainder += kNanosPerDay;
        days -= 1;
    }
    CivilTime civil = civil_from_days(days);
    civil.hour = static_cast<unsigned>(remainder / kNanosPerHour);
    remainder %= kNanosPerHour;
    civil.minute = static_cast<unsigned>(remainder / kNanosPerMinute);
    remainder %= kNanosPerMinute;
    civil.second = static_cast<unsigned>(remainder / kNanosPerSecond);
    civil.nanosecond = static_cast<std::uint32_t>(remainder % kNanosPerSecond);
    if (civil.year < 1 || civil.year > 9999) {
        return make_error(Code::TimestampOutOfRange, "instant is outside the canonical civil year range");
    }
    return civil;
}

std::string Instant::format() const {
    auto civil = to_civil();
    if (!civil) {
        return std::string();
    }
    const CivilTime& value = civil.value();
    std::string out;
    out.reserve(30);
    append_four_digits(out, value.year);
    out.push_back('-');
    append_two_digits(out, value.month);
    out.push_back('-');
    append_two_digits(out, value.day);
    out.push_back('T');
    append_two_digits(out, value.hour);
    out.push_back(':');
    append_two_digits(out, value.minute);
    out.push_back(':');
    append_two_digits(out, value.second);
    out.push_back('.');
    char digits[16];
    std::snprintf(digits, sizeof(digits), "%09u", value.nanosecond);
    out.append(digits);
    out.push_back('Z');
    return out;
}

std::string Instant::format_date() const {
    auto civil = to_civil();
    if (!civil) {
        return std::string();
    }
    std::string out;
    out.reserve(10);
    append_four_digits(out, civil.value().year);
    out.push_back('-');
    append_two_digits(out, civil.value().month);
    out.push_back('-');
    append_two_digits(out, civil.value().day);
    return out;
}

Result<Instant> Instant::add(const Duration& duration) const {
    std::int64_t delta = 0;
    if (!checked_add_i64(nanos_, static_cast<std::int64_t>(duration.nanos()), delta)) {
        return make_error(Code::TimestampOutOfRange, "instant plus duration overflows");
    }
    return from_unix_nanos(delta);
}

Result<Instant> Instant::subtract(const Duration& duration) const {
    std::int64_t delta = 0;
    if (!checked_add_i64(nanos_, -static_cast<std::int64_t>(duration.nanos()), delta)) {
        return make_error(Code::TimestampOutOfRange, "instant minus duration overflows");
    }
    return from_unix_nanos(delta);
}

Result<Delta> Instant::difference(const Instant& other) const {
    // The signed distance is reported only when it is exactly representable.
    const std::int64_t left = nanos_;
    const std::int64_t right = other.nanos_;
    if (left >= right) {
        const std::uint64_t magnitude = static_cast<std::uint64_t>(left) - static_cast<std::uint64_t>(right);
        if (magnitude > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
            return make_error(Code::IntegerOverflow, "instant difference is not representable");
        }
        return Delta::from_nanos(static_cast<std::int64_t>(magnitude));
    }
    const std::uint64_t magnitude = static_cast<std::uint64_t>(right) - static_cast<std::uint64_t>(left);
    if (magnitude > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
        return make_error(Code::IntegerOverflow, "instant difference is not representable");
    }
    return Delta::from_nanos(-static_cast<std::int64_t>(magnitude));
}

}  // namespace maintpol
