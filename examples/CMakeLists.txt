set(AV_EXAMPLES
  example_create_and_attach
  example_capability_projection
  example_two_virtuals_one_device
  example_backing_replacement
  example_stale_authority
  example_synthetic_migration
  example_restart_recovery
  example_cuda_virtual_backing
  example_control_plane_client
)

foreach(example IN LISTS AV_EXAMPLES)
  add_executable(${example} ${example}.cpp)
  av_apply_warnings(${example})
  target_link_libraries(${example} PRIVATE av_core)
  if(WIN32)
    target_compile_definitions(${example} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
  endif()
endforeach()

if(TARGET av_cuda)
  target_link_libraries(example_cuda_virtual_backing PRIVATE av_cuda)
  target_compile_definitions(example_cuda_virtual_backing PRIVATE AV_WITH_CUDA=1)
endif()

install(TARGETS ${AV_EXAMPLES} RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}/examples")
