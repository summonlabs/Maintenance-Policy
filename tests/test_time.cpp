#include <string>
#include <vector>

#include "fixtures.hpp"
#include "harness.hpp"

namespace {

using namespace maintpol;
using namespace maintpol::test;

}  // namespace

MP_TEST(time, calendar_boundaries) {
    MP_CHECK(is_leap_year(2000));
    MP_CHECK(!is_leap_year(1900));
    MP_CHECK(is_leap_year(2024));
    MP_CHECK(!is_leap_year(2100));
    MP_CHECK(is_leap_year(2400));
    MP_CHECK_EQ(days_in_month(2024, 2), 29u);
    MP_CHECK_EQ(days_in_month(1900, 2), 28u);
    MP_CHECK_EQ(days_in_month(2100, 2), 28u);
    MP_CHECK_EQ(days_from_civil(1970, 1, 1), std::int64_t(0));
    MP_CHECK_EQ(days_from_civil(1969, 12, 31), std::int64_t(-1));
    MP_CHECK_EQ(days_from_civil(2000, 3, 1) - days_from_civil(2000, 2, 28), std::int64_t(2));
    MP_CHECK_EQ(days_from_civil(1900, 3, 1) - days_from_civil(1900, 2, 28), std::int64_t(1));
    const std::vector<int> years = {1, 1600, 1900, 1970, 2000, 2024, 2100, 9999};
    for (int year : years) {
        for (unsigned month = 1; month <= 12; ++month) {
            const CivilTime civil = civil_from_days(days_from_civil(year, month, 1));
            MP_CHECK(civil.year == year);
            MP_CHECK(civil.month == month);
            MP_CHECK(civil.day == 1u);
        }
    }
}

MP_TEST(time, leap_day_validation) {
    MP_CHECK(Instant::parse("2000-02-29T00:00:00Z").has_value());
    MP_CHECK(Instant::parse("2024-02-29T23:59:59.999999999Z").has_value());
    MP_CHECK_CODE(Instant::parse("1900-02-29T00:00:00Z"), Code::CalendarInvalid);
    MP_CHECK_CODE(Instant::parse("2023-02-29T00:00:00Z"), Code::CalendarInvalid);
    MP_CHECK_CODE(Instant::parse("2100-02-29T00:00:00Z"), Code::CalendarInvalid);
    MP_CHECK_CODE(Instant::parse("2023-04-31T00:00:00Z"), Code::CalendarInvalid);
}

MP_TEST(time, instant_range_limits) {
    const Instant minimum = MP_REQUIRE(Instant::from_unix_nanos(INT64_MIN));
    MP_CHECK_EQ(minimum.format(), std::string("1677-09-21T00:12:43.145224192Z"));
    const Instant maximum = MP_REQUIRE(Instant::from_unix_nanos(INT64_MAX));
    MP_CHECK_EQ(maximum.format(), std::string("2262-04-11T23:47:16.854775807Z"));
    MP_CHECK_CODE(Instant::parse("2262-04-11T23:47:16.854775808Z"), Code::TimestampOutOfRange);
    MP_CHECK_CODE(Instant::parse("1677-09-21T00:12:43.145224191Z"), Code::TimestampOutOfRange);
    MP_CHECK_CODE(Instant::parse("9999-12-31T23:59:59.999999999Z"), Code::TimestampOutOfRange);
    MP_CHECK_CODE(Instant::parse("0001-01-01T00:00:00Z"), Code::TimestampOutOfRange);
}

MP_TEST(time, pre_epoch_and_offsets) {
    MP_CHECK_EQ(instant("1969-12-31T23:59:59.999999999Z").unix_nanos(), std::int64_t(-1));
    MP_CHECK_EQ(instant("1970-01-01T00:00:00.000000001Z").unix_nanos(), std::int64_t(1));
    MP_CHECK_EQ(instant("2026-01-01T05:30:00+05:30").format(), std::string("2026-01-01T00:00:00.000000000Z"));
    MP_CHECK_EQ(instant("2025-12-31T19:00:00-05:00").format(), std::string("2026-01-01T00:00:00.000000000Z"));
    MP_CHECK_EQ(instant("2026-01-01t00:00:00z").format(), std::string("2026-01-01T00:00:00.000000000Z"));
    MP_CHECK_EQ(instant("2026-01-01T14:00:00+14:00").format(), std::string("2026-01-01T00:00:00.000000000Z"));
    MP_CHECK_CODE(Instant::parse("2026-01-01T00:00:00+18:01"), Code::OffsetOutOfRange);
    MP_CHECK_CODE(Instant::parse("2026-01-01T00:00:00+19:00"), Code::OffsetOutOfRange);
    MP_CHECK_CODE(Instant::parse("2026-01-01T00:00:00"), Code::TimestampMalformed);
    MP_CHECK_CODE(Instant::parse("2026-01-01 00:00:00Z"), Code::TimestampMalformed);
    MP_CHECK_CODE(Instant::parse("2026-1-01T00:00:00Z"), Code::TimestampMalformed);
    MP_CHECK_CODE(Instant::parse("2026-01-01T00:00:00.1234567891Z"), Code::TimestampMalformed);
    MP_CHECK_CODE(Instant::parse("2026-01-01T00:00:00.Z"), Code::TimestampMalformed);
    MP_CHECK_CODE(Instant::parse("2026-01-01T24:00:00Z"), Code::CalendarInvalid);
    MP_CHECK_CODE(Instant::parse("2026-01-01T00:60:00Z"), Code::CalendarInvalid);
}

MP_TEST(time, arithmetic_is_checked) {
    const Instant base = instant("2026-01-01T00:00:00Z");
    const Instant later = MP_REQUIRE(base.add(duration("PT1H")));
    MP_CHECK_EQ(later.format(), std::string("2026-01-01T01:00:00.000000000Z"));
    const Delta delta = MP_REQUIRE(later.difference(base));
    MP_CHECK_EQ(delta.nanos(), std::int64_t(3600000000000));
    const Delta negative = MP_REQUIRE(base.difference(later));
    MP_CHECK_EQ(negative.nanos(), std::int64_t(-3600000000000));
    const Instant maximum = MP_REQUIRE(Instant::from_unix_nanos(INT64_MAX));
    MP_CHECK_CODE(maximum.add(duration("PT1S")), Code::TimestampOutOfRange);
    const Instant minimum = MP_REQUIRE(Instant::from_unix_nanos(INT64_MIN));
    MP_CHECK_CODE(minimum.subtract(duration("PT1S")), Code::TimestampOutOfRange);
    MP_CHECK_CODE(minimum.difference(maximum), Code::IntegerOverflow);
}

MP_TEST(time, duration_parsing) {
    MP_CHECK_EQ(duration("PT0S").nanos(), std::uint64_t(0));
    MP_CHECK_EQ(duration("PT1H").nanos(), std::uint64_t(3600000000000ull));
    MP_CHECK_EQ(duration("P1D").nanos(), std::uint64_t(86400000000000ull));
    MP_CHECK_EQ(duration("P1DT1S").format(), std::string("P1DT0H0M1S"));
    MP_CHECK_EQ(duration("PT0.000000001S").nanos(), std::uint64_t(1));
    MP_CHECK_CODE(Duration::parse("1H"), Code::ValueMalformed);
    MP_CHECK_CODE(Duration::parse("PT"), Code::ValueMalformed);
    MP_CHECK_CODE(Duration::parse("PT1X"), Code::ValueMalformed);
    MP_CHECK_CODE(Duration::parse("PT1H2H"), Code::ValueMalformed);
    MP_CHECK_CODE(Duration::parse("PT1M1D"), Code::ValueMalformed);
    MP_CHECK_CODE(Duration::parse("PT99999999999999999999S"), Code::IntegerOverflow);
    const Duration day = duration("P1D");
    const Duration day_twice = MP_REQUIRE(day.multiply(2));
    MP_CHECK_EQ(day_twice.format(), std::string("P2DT0H0M0S"));
    const Duration sum = MP_REQUIRE(day.add(day_twice));
    MP_CHECK_EQ(sum.format(), std::string("P3DT0H0M0S"));
}
