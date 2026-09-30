cmake_minimum_required(VERSION 3.25)

project(MaintenancePolicy
    VERSION 1.0.0
    DESCRIPTION "Facility maintenance policy evaluation runtime"
    HOMEPAGE_URL "https://github.com/summonlabs/Maintenance-Policy"
    LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

option(MAINTPOL_BUILD_CLI "Build the maintpol command line tool" ON)
option(MAINTPOL_BUILD_TESTS "Build the maintpol test suite" ON)
option(MAINTPOL_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(MAINTPOL_ENABLE_ASAN "Build first-party targets with AddressSanitizer where the toolchain supports it" OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Strict first-party warning policy.
# ---------------------------------------------------------------------------
function(maintpol_strict_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
        if(MAINTPOL_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
            -Wnon-virtual-dtor -Wcast-qual -Wdouble-promotion -Wformat=2 -Wundef
            -Wold-style-cast -Woverloaded-virtual)
        if(MAINTPOL_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Optional AddressSanitizer instrumentation for first-party targets.
# ---------------------------------------------------------------------------
function(maintpol_address_sanitizer target)
    if(NOT MAINTPOL_ENABLE_ASAN)
        return()
    endif()
    if(MSVC)
        target_compile_options(${target} PRIVATE /fsanitize=address)
        target_link_options(${target} PRIVATE /INCREMENTAL:NO)
    else()
        target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address)
    endif()
endfunction()

set(MAINTPOL_PUBLIC_HEADERS
    include/maintpol/version.hpp
    include/maintpol/error.hpp
    include/maintpol/types.hpp
    include/maintpol/digest.hpp
    include/maintpol/time.hpp
    include/maintpol/canonical.hpp
    include/maintpol/policy.hpp
    include/maintpol/request.hpp
    include/maintpol/decision.hpp
    include/maintpol/engine.hpp
    include/maintpol/text.hpp
    include/maintpol/lock.hpp
    include/maintpol/fileio.hpp
    include/maintpol/fault.hpp
    include/maintpol/store.hpp
    include/maintpol/selftest.hpp)

set(MAINTPOL_SOURCES
    src/error.cpp
    src/types.cpp
    src/digest.cpp
    src/time.cpp
    src/canonical.cpp
    src/policy.cpp
    src/request.cpp
    src/decision.cpp
    src/engine.cpp
    src/text.cpp
    src/lock.cpp
    src/fileio.cpp
    src/fault.cpp
    src/store.cpp
    src/selftest.cpp)

add_library(maintpol ${MAINTPOL_SOURCES} ${MAINTPOL_PUBLIC_HEADERS})
add_library(SummonLabs::maintpol ALIAS maintpol)

target_include_directories(maintpol PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_compile_features(maintpol PUBLIC cxx_std_20)
maintpol_strict_warnings(maintpol)
maintpol_address_sanitizer(maintpol)

if(BUILD_SHARED_LIBS)
    target_compile_definitions(maintpol
        PUBLIC MAINTPOL_SHARED
        PRIVATE MAINTPOL_BUILDING_LIBRARY)
endif()

set_target_properties(maintpol PROPERTIES
    OUTPUT_NAME maintpol
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------------------
# Command line tool.
# ---------------------------------------------------------------------------
if(MAINTPOL_BUILD_CLI)
    add_executable(maintpol_cli cli/main.cpp cli/commands.cpp cli/commands.hpp)
    set_target_properties(maintpol_cli PROPERTIES OUTPUT_NAME maintpol)
    target_link_libraries(maintpol_cli PRIVATE maintpol)
    if(WIN32)
        # The command line tool derives new authority key material from the
        # operating system random source.
        target_link_libraries(maintpol_cli PRIVATE bcrypt)
    endif()
    target_compile_features(maintpol_cli PRIVATE cxx_std_20)
    maintpol_strict_warnings(maintpol_cli)
    maintpol_address_sanitizer(maintpol_cli)
endif()

# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------
if(MAINTPOL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Install and package.
# ---------------------------------------------------------------------------
install(TARGETS maintpol
    EXPORT maintpolTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(MAINTPOL_BUILD_CLI)
    install(TARGETS maintpol_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT maintpolTargets
    NAMESPACE SummonLabs::
    FILE maintpolTargets.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/maintpol)

configure_package_config_file(
    cmake/maintpolConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/maintpolConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/maintpol)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/maintpolConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/maintpolConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/maintpolConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/maintpol)

install(FILES LICENSE NOTICE README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
