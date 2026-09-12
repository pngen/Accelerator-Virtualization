set(AV_APP_TARGETS av_coordinator av_agent av_cli)

add_executable(av_coordinator coordinator_main.cpp)
add_executable(av_agent agent_main.cpp)
add_executable(av_cli cli_main.cpp)

foreach(app IN LISTS AV_APP_TARGETS)
  av_apply_warnings(${app})
  target_include_directories(${app} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(${app} PRIVATE av_core)
  if(WIN32)
    target_compile_definitions(${app} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
  endif()
endforeach()

if(TARGET av_cuda)
  target_link_libraries(av_agent PRIVATE av_cuda)
  target_compile_definitions(av_agent PRIVATE AV_WITH_CUDA=1)
endif()

install(TARGETS ${AV_APP_TARGETS} RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
