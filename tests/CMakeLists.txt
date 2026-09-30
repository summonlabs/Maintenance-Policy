set(MAINTPOL_TEST_SOURCES
    main.cpp
    test_digest.cpp
    test_time.cpp
    test_canonical.cpp
    test_policy.cpp
    test_engine.cpp
    test_store.cpp
    test_adversarial.cpp
    test_property.cpp
    test_multiprocess.cpp
    test_cli.cpp)

add_executable(maintpol_tests ${MAINTPOL_TEST_SOURCES} harness.hpp harness.cpp fixtures.hpp fixtures.cpp)
if(MSVC)
    # The harness reads MAINTPOL_CLI and MAINTPOL_HELPER through getenv.
    target_compile_definitions(maintpol_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
target_link_libraries(maintpol_tests PRIVATE maintpol)
target_compile_features(maintpol_tests PRIVATE cxx_std_20)
maintpol_strict_warnings(maintpol_tests)
maintpol_address_sanitizer(maintpol_tests)

add_executable(maintpol_helper helper_child.cpp)
target_link_libraries(maintpol_helper PRIVATE maintpol)
target_compile_features(maintpol_helper PRIVATE cxx_std_20)
maintpol_strict_warnings(maintpol_helper)
maintpol_address_sanitizer(maintpol_helper)

add_test(NAME maintpol.suite COMMAND $<TARGET_FILE:maintpol_tests>)
set_tests_properties(maintpol.suite PROPERTIES
    ENVIRONMENT "MAINTPOL_CLI=$<TARGET_FILE:maintpol_cli>;MAINTPOL_HELPER=$<TARGET_FILE:maintpol_helper>")

add_test(NAME maintpol.cli.selftest COMMAND $<TARGET_FILE:maintpol_cli> selftest --quiet)
add_test(NAME maintpol.cli.version COMMAND $<TARGET_FILE:maintpol_cli> version)

foreach(group IN ITEMS digest time canonical policy engine store adversarial property multiprocess cli)
    add_test(NAME maintpol.suite.${group} COMMAND $<TARGET_FILE:maintpol_tests> --group ${group})
    set_tests_properties(maintpol.suite.${group} PROPERTIES
        ENVIRONMENT "MAINTPOL_CLI=$<TARGET_FILE:maintpol_cli>;MAINTPOL_HELPER=$<TARGET_FILE:maintpol_helper>")
endforeach()
