
add_executable(av_bench bench.cpp)
av_apply_warnings(av_bench)
target_link_libraries(av_bench PRIVATE av_core)
if(WIN32)
  target_compile_definitions(av_bench PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()
install(TARGETS av_bench RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
