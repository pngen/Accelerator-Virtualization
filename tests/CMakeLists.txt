
# The test harness. Each suite is its own executable so a hang can be localised
# to an exact suite, case and phase with the --case selector.
add_library(av_testkit STATIC testkit.cpp process.cpp support.cpp)
target_include_directories(av_testkit PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(av_testkit PUBLIC av_core)
av_apply_warnings(av_testkit)
if(WIN32)
  target_compile_definitions(av_testkit PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

set(AV_SUITES
  unit_core
  unit_runtime
  property
  concurrency
  adversarial
  scale
  multiprocess
  cuda_hardware
)

foreach(suite IN LISTS AV_SUITES)
  add_executable(av_test_${suite} ${suite}.cpp)
  target_link_libraries(av_test_${suite} PRIVATE av_testkit)
  av_apply_warnings(av_test_${suite})
  add_test(NAME ${suite} COMMAND av_test_${suite})
  set_tests_properties(${suite} PROPERTIES TIMEOUT 1800)
endforeach()

if(TARGET av_cuda)
  target_link_libraries(av_test_cuda_hardware PRIVATE av_cuda)
  target_compile_definitions(av_test_cuda_hardware PRIVATE AV_WITH_CUDA=1)
endif()

# The multiprocess suite drives the real applications, so they must be built.
if(TARGET av_coordinator)
  add_dependencies(av_test_multiprocess av_coordinator av_agent)
endif()
