
cmake_minimum_required(VERSION 3.21)

project(AcceleratorVirtualization
  VERSION 1.0.0
  DESCRIPTION "Vendor-neutral C++20 runtime for governing virtual accelerator identity, tenancy, isolation and lifecycle across physical accelerators"
  HOMEPAGE_URL "https://github.com/pngen/Accelerator-Virtualization"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(AV_BUILD_APPS       "Build av_coordinator, av_agent and av_cli"          ON)
option(AV_BUILD_TESTS      "Build the Accelerator Virtualization test suites"  ON)
option(AV_BUILD_EXAMPLES   "Build the runnable examples"                       ON)
option(AV_BUILD_BENCHMARKS "Build the benchmarks"                              ON)
option(AV_ENABLE_CUDA      "Build the optional CUDA adapter when a toolkit is found" ON)
option(AV_ENABLE_ASAN      "Build with AddressSanitizer instrumentation"       OFF)
option(AV_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors"   ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(PROJECT_IS_TOP_LEVEL)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
  foreach(cfg IN ITEMS DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${cfg} "${CMAKE_BINARY_DIR}/lib")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${cfg} "${CMAKE_BINARY_DIR}/lib")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${cfg} "${CMAKE_BINARY_DIR}/bin")
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Warning discipline. Strict first-party warnings with no global suppressions;
# the settings are applied per first-party target so that exported targets do
# not impose this project's warning policy on downstream consumers.
# ---------------------------------------------------------------------------
function(av_apply_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /EHsc /Zc:__cplusplus /Zc:preprocessor)
    if(AV_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
    if(AV_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
  if(AV_ENABLE_ASAN)
    if(MSVC)
      target_compile_options(${target} PRIVATE /fsanitize=address)
      target_link_options(${target} PRIVATE /INCREMENTAL:NO)
    else()
      target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer -g)
      target_link_options(${target} PRIVATE -fsanitize=address)
    endif()
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
add_subdirectory(src)
if(AV_ENABLE_CUDA AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/cuda/CMakeLists.txt")
  add_subdirectory(src/cuda)
endif()
if(AV_BUILD_APPS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/apps/CMakeLists.txt")
  add_subdirectory(apps)
endif()
if(AV_BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
  enable_testing()
  add_subdirectory(tests)
endif()
if(AV_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt")
  add_subdirectory(examples)
endif()
if(AV_BUILD_BENCHMARKS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/CMakeLists.txt")
  add_subdirectory(benchmarks)
endif()

# ---------------------------------------------------------------------------
# Install / export / package config
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(AV_INSTALL_TARGETS av_core)
if(TARGET av_cuda)
  list(APPEND AV_INSTALL_TARGETS av_cuda)
  set(AV_CUDA_INSTALLED TRUE)
else()
  set(AV_CUDA_INSTALLED FALSE)
endif()

install(TARGETS ${AV_INSTALL_TARGETS}
  EXPORT AcceleratorVirtualizationTargets
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/av"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.hpp")

install(EXPORT AcceleratorVirtualizationTargets
  FILE AcceleratorVirtualizationTargets.cmake
  NAMESPACE AcceleratorVirtualization::
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/AcceleratorVirtualization")

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/AcceleratorVirtualizationConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/AcceleratorVirtualizationConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/AcceleratorVirtualization")

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/AcceleratorVirtualizationConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/AcceleratorVirtualizationConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/AcceleratorVirtualizationConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/AcceleratorVirtualization")

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/AcceleratorVirtualization")
