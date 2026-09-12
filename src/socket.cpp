// Accelerator Virtualization - vendor-neutral virtual accelerator runtime.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "av/socket.hpp"

#include <algorithm>
#include <cstring>

#include "av/hash.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace av {
namespace {

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
constexpr int kShutdownBoth = SD_BOTH;
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
constexpr int kShutdownBoth = SHUT_RDWR;
#endif

std::once_flag g_network_once;
Status g_network_status{};

Status ensure_network() {
  std::call_once(g_network_once, []() {
#ifdef _WIN32
    WSADATA data{};
    const int result = ::WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
      g_network_status = Status(StatusCode::IoFailure, "WSAStartup failed with code " + std::to_string(result));
      return;
    }
    if (LOBYTE(data.wVersion) != 2 || HIBYTE(data.wVersion) != 2) {
      g_network_status = Status(StatusCode::IoFailure, "no usable Winsock 2.2 implementation is available");
      return;
    }
#endif
    g_network_status = Status{};
  });
  return g_network_status;
}

Status last_socket_error(std::string_view what) {
#ifdef _WIN32
  const int code = ::WSAGetLastError();
#else
  const int code = errno;
#endif
  return Status(StatusCode::IoFailure, std::string(what) + " failed with socket error " + std::to_string(code));
}

std::string describe_peer(const sockaddr_storage& address) {
  char host[INET6_ADDRSTRLEN] = {};
  char service[16] = {};
  const auto* base = reinterpret_cast<const sockaddr*>(&address);
  const socklen_t length = address.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
  if (::getnameinfo(base, length, host, sizeof(host), service, sizeof(service),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
    return "unknown";
  }
  return std::string(host) + ":" + service;
}

}  // namespace

Status network_init() { return ensure_network(); }

Socket::Socket() noexcept : handle_(static_cast<std::uintptr_t>(kInvalidSocket)) {}

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept
    : handle_(other.handle_), peer_(std::move(other.peer_)), sent_(other.sent_), received_(other.received_) {
  other.handle_ = static_cast<std::uintptr_t>(kInvalidSocket);
  other.sent_ = 0;
  other.received_ = 0;
}

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    peer_ = std::move(other.peer_);
    sent_ = other.sent_;
    received_ = other.received_;
    other.handle_ = static_cast<std::uintptr_t>(kInvalidSocket);
    other.sent_ = 0;
    other.received_ = 0;
  }
  return *this;
}

Socket Socket::adopt(std::uintptr_t native_handle, std::string peer) {
  Socket socket;
  socket.handle_ = native_handle;
  socket.peer_ = std::move(peer);
  return socket;
}

bool Socket::valid() const noexcept { return handle_ != static_cast<std::uintptr_t>(kInvalidSocket); }

void Socket::close() noexcept {
  if (!valid()) return;
  const NativeSocket native = static_cast<NativeSocket>(handle_);
#ifdef _WIN32
  ::closesocket(native);
#else
  ::close(native);
#endif
  handle_ = static_cast<std::uintptr_t>(kInvalidSocket);
}

std::string Socket::peer() const { return peer_; }

Result<Socket> Socket::connect(std::string_view host, std::uint16_t port) {
  const Status ready = ensure_network();
  if (!ready.ok()) return ready;
  if (host.empty()) return Status(StatusCode::InvalidArgument, "host must not be empty");
  if (port == 0) return Status(StatusCode::InvalidArgument, "port must not be zero");

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  const std::string host_text(host);
  const std::string port_text = std::to_string(port);
  addrinfo* results = nullptr;
  const int resolved = ::getaddrinfo(host_text.c_str(), port_text.c_str(), &hints, &results);
  if (resolved != 0 || results == nullptr) {
    return Status(StatusCode::IoFailure, "cannot resolve '" + host_text + "'");
  }

  Socket socket;
  Status failure = Status(StatusCode::IoFailure, "no usable address for '" + host_text + "'");
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    const NativeSocket native = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (native == kInvalidSocket) {
      failure = last_socket_error("socket");
      continue;
    }
    if (::connect(native, candidate->ai_addr, static_cast<socklen_t>(candidate->ai_addrlen)) == 0) {
      socket.handle_ = static_cast<std::uintptr_t>(native);
      sockaddr_storage local{};
      socklen_t length = sizeof(local);
      char host_buffer[INET6_ADDRSTRLEN] = {};
      char service_buffer[16] = {};
      if (::getsockname(native, reinterpret_cast<sockaddr*>(&local), &length) == 0 &&
          ::getnameinfo(reinterpret_cast<sockaddr*>(&local), length, host_buffer, sizeof(host_buffer),
                        service_buffer, sizeof(service_buffer), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        socket.peer_ = std::string(host_buffer) + ":" + service_buffer;
      } else {
        socket.peer_ = host_text + ":" + port_text;
      }
      const Status configured = socket.set_nodelay(true);
      (void)configured;
      ::freeaddrinfo(results);
      return socket;
    }
    failure = last_socket_error("connect");
#ifdef _WIN32
    ::closesocket(native);
#else
    ::close(native);
#endif
  }
  ::freeaddrinfo(results);
  return failure;
}

Status Socket::send_all(ByteSpan data) {
  if (!valid()) return Status(StatusCode::ConnectionLost, "socket is not open");
  std::size_t offset = 0;
  while (offset < data.size()) {
    const int chunk = static_cast<int>(std::min<std::size_t>(data.size() - offset, 1u << 20));
    const int written = ::send(static_cast<NativeSocket>(handle_),
                               reinterpret_cast<const char*>(data.data() + offset), chunk, 0);
    if (written <= 0) return last_socket_error("send");
    offset += static_cast<std::size_t>(written);
    sent_ += static_cast<std::size_t>(written);
  }
  return Status{};
}

Result<std::size_t> Socket::recv_some(MutableByteSpan buffer) {
  if (!valid()) return Status(StatusCode::ConnectionLost, "socket is not open");
  if (buffer.empty()) return std::size_t{0};
  const int chunk = static_cast<int>(std::min<std::size_t>(buffer.size(), 1u << 20));
  const int received =
      ::recv(static_cast<NativeSocket>(handle_), reinterpret_cast<char*>(buffer.data()), chunk, 0);
  if (received < 0) return last_socket_error("recv");
  const std::size_t count = static_cast<std::size_t>(received);
  received_ += count;
  return count;
}

Status Socket::shutdown_both() {
  if (!valid()) return Status{};
  if (::shutdown(static_cast<NativeSocket>(handle_), kShutdownBoth) != 0) {
    return last_socket_error("shutdown");
  }
  return Status{};
}

Status Socket::set_nodelay(bool enable) {
  if (!valid()) return Status(StatusCode::ConnectionLost, "socket is not open");
  const int value = enable ? 1 : 0;
  if (::setsockopt(static_cast<NativeSocket>(handle_), IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
    return last_socket_error("setsockopt(TCP_NODELAY)");
  }
  return Status{};
}

Listener::Listener() noexcept : handle_(static_cast<std::uintptr_t>(kInvalidSocket)) {}

Listener::~Listener() { close(); }

Listener::Listener(Listener&& other) noexcept : handle_(other.handle_), port_(other.port_) {
  other.handle_ = static_cast<std::uintptr_t>(kInvalidSocket);
  other.port_ = 0;
}

Listener& Listener::operator=(Listener&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    port_ = other.port_;
    other.handle_ = static_cast<std::uintptr_t>(kInvalidSocket);
    other.port_ = 0;
  }
  return *this;
}

bool Listener::valid() const noexcept { return handle_ != static_cast<std::uintptr_t>(kInvalidSocket); }

void Listener::close() noexcept {
  if (!valid()) return;
  const NativeSocket native = static_cast<NativeSocket>(handle_);
#ifdef _WIN32
  ::closesocket(native);
#else
  ::close(native);
#endif
  handle_ = static_cast<std::uintptr_t>(kInvalidSocket);
}

Result<Listener> Listener::bind(std::string_view host, std::uint16_t port, int backlog) {
  const Status ready = ensure_network();
  if (!ready.ok()) return ready;
  if (backlog <= 0 || backlog > 1024) {
    return Status(StatusCode::InvalidArgument, "backlog must be between 1 and 1024");
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  const std::string host_text(host);
  const std::string port_text = std::to_string(port);
  addrinfo* results = nullptr;
  const int resolved = ::getaddrinfo(host_text.empty() ? nullptr : host_text.c_str(), port_text.c_str(), &hints,
                                     &results);
  if (resolved != 0 || results == nullptr) {
    return Status(StatusCode::IoFailure, "cannot resolve bind address");
  }

  Listener listener;
  Status failure = Status(StatusCode::IoFailure, "no usable bind address");
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    const NativeSocket native = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (native == kInvalidSocket) {
      failure = last_socket_error("socket");
      continue;
    }
    const int reuse = 1;
    ::setsockopt(native, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    if (::bind(native, candidate->ai_addr, static_cast<socklen_t>(candidate->ai_addrlen)) != 0) {
      failure = last_socket_error("bind");
#ifdef _WIN32
      ::closesocket(native);
#else
      ::close(native);
#endif
      continue;
    }
    if (::listen(native, backlog) != 0) {
      failure = last_socket_error("listen");
#ifdef _WIN32
      ::closesocket(native);
#else
      ::close(native);
#endif
      continue;
    }
    sockaddr_storage local{};
    socklen_t length = sizeof(local);
    if (::getsockname(native, reinterpret_cast<sockaddr*>(&local), &length) != 0) {
      failure = last_socket_error("getsockname");
#ifdef _WIN32
      ::closesocket(native);
#else
      ::close(native);
#endif
      continue;
    }
    listener.handle_ = static_cast<std::uintptr_t>(native);
    if (local.ss_family == AF_INET) {
      listener.port_ = ntohs(reinterpret_cast<const sockaddr_in*>(&local)->sin_port);
    } else if (local.ss_family == AF_INET6) {
      listener.port_ = ntohs(reinterpret_cast<const sockaddr_in6*>(&local)->sin6_port);
    }
    ::freeaddrinfo(results);
    return listener;
  }
  ::freeaddrinfo(results);
  return failure;
}

Result<Socket> Listener::accept() {
  if (!valid()) return Status(StatusCode::ConnectionLost, "listener is not open");
  sockaddr_storage address{};
  socklen_t length = sizeof(address);
  const NativeSocket native =
      ::accept(static_cast<NativeSocket>(handle_), reinterpret_cast<sockaddr*>(&address), &length);
  if (native == kInvalidSocket) return last_socket_error("accept");
  Socket socket = Socket::adopt(static_cast<std::uintptr_t>(native), describe_peer(address));
  const Status configured = socket.set_nodelay(true);
  (void)configured;
  const int keepalive = 1;
  ::setsockopt(native, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&keepalive), sizeof(keepalive));
  return socket;
}

// ---- FrameChannel --------------------------------------------------------

FrameChannel::FrameChannel(Socket socket) : socket_(std::move(socket)), open_(socket_.valid()) {}

FrameChannel::~FrameChannel() {
  if (open_.load()) {
    const Status ignored = close();
    (void)ignored;
  }
}

FrameChannel::FrameChannel(FrameChannel&& other) noexcept
    : socket_(std::move(other.socket_)),
      stream_(other.stream_.max_payload()),
      pending_(std::move(other.pending_)),
      open_(other.open_.load()),
      frames_sent_(other.frames_sent_),
      frames_received_(other.frames_received_) {
  other.open_.store(false);
  other.frames_sent_ = 0;
  other.frames_received_ = 0;
}

FrameChannel& FrameChannel::operator=(FrameChannel&& other) noexcept {
  if (this != &other) {
    socket_ = std::move(other.socket_);
    stream_.reset();
    stream_.set_max_payload(other.stream_.max_payload());
    pending_ = std::move(other.pending_);
    open_.store(other.open_.load());
    frames_sent_ = other.frames_sent_;
    frames_received_ = other.frames_received_;
    other.open_.store(false);
    other.frames_sent_ = 0;
    other.frames_received_ = 0;
  }
  return *this;
}

Status FrameChannel::send(std::uint16_t type, RequestId request, ByteSpan payload, std::uint32_t flags) {
  if (!open_.load()) return Status(StatusCode::ConnectionLost, "channel is closed");
  FrameHeader header;
  header.magic = kFrameMagic;
  header.version = protocol_version();
  header.type = type;
  header.flags = flags;
  header.request = request.value();
  header.payload_length = static_cast<std::uint32_t>(payload.size());
  header.payload_crc = Crc32c::compute(payload.data(), payload.size());
  const std::vector<Byte> bytes = encode_frame(header, payload);

  std::lock_guard<std::mutex> lock(send_mutex_);
  const Status status = socket_.send_all(ByteSpan{bytes.data(), bytes.size()});
  if (!status.ok()) {
    open_.store(false);
    return status;
  }
  ++frames_sent_;
  return Status{};
}

Result<FrameStream::Frame> FrameChannel::receive() {
  if (!pending_.empty()) {
    FrameStream::Frame frame = std::move(pending_.front());
    pending_.pop_front();
    ++frames_received_;
    return frame;
  }
  if (!open_.load()) return Status(StatusCode::ConnectionLost, "channel is closed");

  std::vector<Byte> buffer(64u * 1024u);
  std::vector<FrameStream::Frame> frames;
  for (;;) {
    auto received = socket_.recv_some(MutableByteSpan{buffer.data(), buffer.size()});
    if (!received.ok()) {
      open_.store(false);
      return Status(StatusCode::ConnectionLost, received.status().to_string());
    }
    if (*received == 0) {
      open_.store(false);
      return Status(StatusCode::ConnectionLost, "peer closed the connection");
    }
    frames.clear();
    const Status fed = stream_.feed(ByteSpan{buffer.data(), *received}, frames);
    if (!fed.ok()) {
      open_.store(false);
      return fed;
    }
    if (!frames.empty()) {
      FrameStream::Frame first = std::move(frames.front());
      for (std::size_t i = 1; i < frames.size(); ++i) pending_.push_back(std::move(frames[i]));
      ++frames_received_;
      return first;
    }
  }
}

Status FrameChannel::close() {
  if (!open_.exchange(false)) {
    socket_.close();
    return Status{};
  }
  const Status shutdown = socket_.shutdown_both();
  socket_.close();
  return shutdown;
}

void FrameChannel::interrupt() {
  open_.store(false);
  const Status ignored = socket_.shutdown_both();
  (void)ignored;
}

}  // namespace av
