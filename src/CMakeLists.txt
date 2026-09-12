
add_library(av_core STATIC
  status.cpp
  time.cpp
  backend.cpp
  ids.cpp
  codec.cpp
  taxonomy.cpp
  isolation.cpp
  capability.cpp
  contract.cpp
  lifecycle.cpp
  backing.cpp
  policy.cpp
  migration.cpp
  model.cpp
  audit.cpp
  accounting.cpp
  invariant.cpp
  record_codec.cpp
  state_codec.cpp
  persistence.cpp
  runtime.cpp
  protocol.cpp
  socket.cpp
  client.cpp
  synthetic.cpp
)
add_library(AcceleratorVirtualization::av_core ALIAS av_core)

target_include_directories(av_core
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}")

av_apply_warnings(av_core)
target_compile_definitions(av_core PUBLIC AV_VERSION_STRING="${PROJECT_VERSION}")

if(WIN32)
  target_compile_definitions(av_core PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(av_core PUBLIC ws2_32)
endif()

set_target_properties(av_core PROPERTIES OUTPUT_NAME "accelerator_virtualization")