
find_package(CUDAToolkit QUIET)

if(NOT CUDAToolkit_FOUND)
  message(STATUS "AcceleratorVirtualization: no CUDA toolkit found, the CUDA adapter is not built")
  return()
endif()

enable_language(CUDA)

set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_EXTENSIONS OFF)

# Blackwell (sm_120) needs CUDA 12.8 or newer. On older toolkits fall back to a
# conservative architecture so the adapter still builds and reports honestly.
if(CUDAToolkit_VERSION VERSION_GREATER_EQUAL "12.8")
  set(AV_CUDA_ARCHITECTURES "120" CACHE STRING "CUDA architectures for the adapter")
else()
  set(AV_CUDA_ARCHITECTURES "75" CACHE STRING "CUDA architectures for the adapter")
endif()
set(CMAKE_CUDA_ARCHITECTURES "${AV_CUDA_ARCHITECTURES}")

add_library(av_cuda STATIC
  cuda_adapter.cpp
  vector_add.cu
)
add_library(AcceleratorVirtualization::av_cuda ALIAS av_cuda)

target_include_directories(av_cuda
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

# Strict host warnings for the C++ translation unit only: CUDA device code has
# its own diagnostic surface.
if(MSVC)
  target_compile_options(av_cuda PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:/W4>
    $<$<COMPILE_LANGUAGE:CXX>:/permissive->
    $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
    $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
    $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
    $<$<COMPILE_LANGUAGE:CXX>:/Zc:preprocessor>)
  if(AV_WARNINGS_AS_ERRORS)
    target_compile_options(av_cuda PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/WX>)
  endif()
else()
  target_compile_options(av_cuda PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Wall> $<$<COMPILE_LANGUAGE:CXX>:-Wextra>)
  if(AV_WARNINGS_AS_ERRORS)
    target_compile_options(av_cuda PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Werror>)
  endif()
endif()

if(AV_ENABLE_ASAN)
  target_compile_options(av_cuda PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/fsanitize=address>)
  target_link_options(av_cuda PRIVATE /INCREMENTAL:NO)
endif()

target_link_libraries(av_cuda PUBLIC av_core CUDA::cudart)
set_target_properties(av_cuda PROPERTIES OUTPUT_NAME "accelerator_virtualization_cuda")

message(STATUS "AcceleratorVirtualization: CUDA adapter enabled (toolkit ${CUDAToolkit_VERSION}, arch ${AV_CUDA_ARCHITECTURES})")
