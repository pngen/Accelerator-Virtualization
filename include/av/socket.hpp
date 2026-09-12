// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>

#include "av/codec.hpp"
#include "av/ids.hpp"
#include "av/protocol.hpp"
#include "av/status.hpp"

namespace av {

// Idempotent platform network initialization.
Status network_init();

class Socket {
 public:
  Socket() noexcept;
  ~Socket();
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  static Result<Socket> connect(std::string_view host, std::uint16_t port);
  static Socket adopt(std::uintptr_t native_handle, std::string peer);

  bool valid() const noexcept;
  Status send_all(ByteSpan data);
  // Returns the number of bytes read; zero means the peer closed cleanly.
  Result<std::size_t> recv_some(MutableByteSpan buffer);
  Status shutdown_both();
  void close() noexcept;
  std::string peer() const;
  Status set_nodelay(bool enable);
  std::uintptr_t native() const noexcept { return handle_; }
  std::size_t bytes_sent() const noexcept { return sent_; }
  std::size_t bytes_received() const noexcept { return received_; }

 private:
  std::uintptr_t handle_;
  std::string peer_;
  std::size_t sent_{0};
  std::size_t received_{0};
};

class Listener {
 public:
  Listener() noexcept;
  ~Listener();
  Listener(Listener&& other) noexcept;
  Listener& operator=(Listener&& other) noexcept;
  Listener(const Listener&) = delete;
  Listener& operator=(const Listener&) = delete;

  static Result<Listener> bind(std::string_view host, std::uint16_t port, int backlog = 64);
  Result<Socket> accept();
  std::uint16_t port() const noexcept { return port_; }
  bool valid() const noexcept;
  void close() noexcept;
  std::uintptr_t native() const noexcept { return handle_; }

 private:
  std::uintptr_t handle_;
  std::uint16_t port_{0};
};

// Framed message channel. Sends are serialized; receives are single-consumer.
// interrupt() unblocks a blocked receive without any timing dependency.
class FrameChannel {
 public:
  FrameChannel() = default;
  explicit FrameChannel(Socket socket);
  ~FrameChannel();
  FrameChannel(FrameChannel&& other) noexcept;
  FrameChannel& operator=(FrameChannel&& other) noexcept;
  FrameChannel(const FrameChannel&) = delete;
  FrameChannel& operator=(const FrameChannel&) = delete;

  Status send(std::uint16_t type, RequestId request, ByteSpan payload, std::uint32_t flags);
  Result<FrameStream::Frame> receive();
  Status close();
  void interrupt();
  bool open() const noexcept { return open_.load(); }
  Socket& socket() noexcept { return socket_; }
  std::string peer() const { return socket_.peer(); }
  std::size_t frames_sent() const noexcept { return frames_sent_; }
  std::size_t frames_received() const noexcept { return frames_received_; }

 private:
  Socket socket_{};
  FrameStream stream_{};
  std::deque<FrameStream::Frame> pending_{};
  mutable std::mutex send_mutex_{};
  std::atomic<bool> open_{false};
  std::size_t frames_sent_{0};
  std::size_t frames_received_{0};
};

}  // namespace av
