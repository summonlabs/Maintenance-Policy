cmake_minimum_required(VERSION 3.25)

# An independent consumer of the installed Maintenance Policy package. It is
# built out of tree against an installed prefix only, never against the source
# tree, which is what proves the exported package is complete.
project(maintpol_downstream CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(maintpol CONFIG REQUIRED)

add_executable(maintpol_consumer main.cpp)
target_link_libraries(maintpol_consumer PRIVATE SummonLabs::maintpol)
target_compile_features(maintpol_consumer PRIVATE cxx_std_20)
if(MSVC)
    target_compile_options(maintpol_consumer PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus /EHsc)
else()
    target_compile_options(maintpol_consumer PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
