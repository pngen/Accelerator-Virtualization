// Accelerator Virtualization - CUDA adapter kernel.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// A minimal real kernel used to prove that executed work reaches the physical
// device. It performs no virtualization of its own: virtualization lives in
// the vendor-neutral runtime, not here.
#include <cuda_runtime.h>

namespace {

__global__ void vector_add_kernel(const float* a, const float* b, float* out, int count) {
  const int index = blockIdx.x * blockDim.x + threadIdx.x;
  if (index < count) out[index] = a[index] + b[index];
}

}  // namespace

extern "C" int av_cuda_vector_add(const float* a, const float* b, float* out, int count) {
  if (count <= 0) return 1;
  if (a == nullptr || b == nullptr || out == nullptr) return 2;
  const int threads = 256;
  const int blocks = (count + threads - 1) / threads;
  vector_add_kernel<<<blocks, threads>>>(a, b, out, count);
  const cudaError_t status = cudaGetLastError();
  if (status != cudaSuccess) return static_cast<int>(status);
  const cudaError_t sync = cudaDeviceSynchronize();
  return sync == cudaSuccess ? 0 : static_cast<int>(sync);
}
