#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#ifdef _WIN32
#  define NOMINMAX
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <bcrypt.h>
#  pragma comment(lib, "Ws2_32.lib")
#  pragma comment(lib, "Bcrypt.lib")
using socket_t = SOCKET;
using socket_len_t = int;
static constexpr socket_t BAD_SOCKET = INVALID_SOCKET;
using pollfd_t = WSAPOLLFD;
#else
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
#  ifdef __linux__
#    include <sys/random.h>
#  endif
using socket_t = int;
using socket_len_t = socklen_t;
static constexpr socket_t BAD_SOCKET = -1;
using pollfd_t = struct pollfd;
#endif
namespace py = pybind11;
namespace {
constexpr size_t MAGIC_N = 8;
constexpr size_t EID_N = 8;
constexpr size_t QUEUE_LIMIT = 8;
constexpr size_t MAX_UNAUTH = 65535;
constexpr size_t MAX_AUTH = 33554431;
constexpr size_t UNAUTH_HEAD = 2;
constexpr size_t AUTH_HEAD = 5;
constexpr size_t MAX_INPUT_BUFFER = 33UL * 1024 * 1024;
constexpr size_t MAX_CONNECTIONS = 200;
constexpr size_t MAX_UNAUTH_CONNECTIONS = 128;
constexpr size_t MAX_CONNECTIONS_PER_PEER = 64;
constexpr size_t MAX_PEER_BUCKETS = 4096;
constexpr size_t MAX_NEW_CONNECTIONS_PER_PEER_PER_MINUTE = 120;
constexpr size_t MAX_ACTIVE_EIDS_PER_CONNECTION = 2048;
constexpr size_t MAX_READ_PER_TICK = 64 * 1024;
constexpr size_t MAX_WRITE_PER_TICK = 64 * 1024;
constexpr size_t MAX_ACCEPT_PER_TICK = 32;
constexpr size_t MAX_PARSE_FRAMES_PER_CALL = 32;
constexpr size_t MAX_PARSE_STEPS_PER_CALL = 128;
constexpr size_t MAX_GLOBAL_BUFFERED_BYTES = 512UL * 1024 * 1024;
constexpr size_t MAX_CONNECTION_BUFFERED_BYTES = 128UL * 1024 * 1024;
constexpr size_t MAX_POOL_WORKERS = 64;
constexpr size_t MAX_PENDING_CALLBACKS_MIN = 32;
constexpr size_t MAX_PENDING_CALLBACKS_MAX = 1024;
constexpr size_t MAX_CID_BYTES = 256;
constexpr auto UNAUTH_TIMEOUT = std::chrono::seconds(30);
constexpr auto EID_TTL = std::chrono::minutes(1);
constexpr auto CLEANUP_INTERVAL = std::chrono::seconds(1);
constexpr auto IO_POLL_INTERVAL_MS = 20;
constexpr auto CONNECT_TIMEOUT = std::chrono::seconds(5);
constexpr auto GREETING_TIMEOUT = std::chrono::seconds(5);
#ifdef _WIN32
struct SocketInit {
    SocketInit() {
        WSADATA d{};
        if (WSAStartup(MAKEWORD(2, 2), &d) != 0)
            throw std::runtime_error("WSAStartup failed");
    }
};
#else
struct SocketInit {};
#endif
void init_sockets() {
    static SocketInit initialized;
    (void)initialized;
}
int sockerr() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}
bool interrupted_error(int e) {
#ifdef _WIN32
    return e == WSAEINTR;
#else
    return e == EINTR;
#endif
}
bool would_block(int e) {
#ifdef _WIN32
    return e == WSAEWOULDBLOCK || e == WSAEINTR;
#else
    return e == EAGAIN || e == EWOULDBLOCK || e == EINTR;
#endif
}
void close_sock(socket_t s) {
    if (s == BAD_SOCKET) return;
#ifdef _WIN32
    shutdown(s, SD_BOTH);
    closesocket(s);
#else
    shutdown(s, SHUT_RDWR);
    close(s);
#endif
}
void nonblocking(socket_t s) {
#ifdef _WIN32
    u_long mode = 1;
    if (ioctlsocket(s, FIONBIO, &mode) != 0)
        throw std::runtime_error("ioctlsocket nonblocking failed");
#else
    const int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0 || fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0)
        throw std::runtime_error("fcntl nonblocking failed");
#endif
}
void tune_socket(socket_t s) {
    int buffer_size = 64 * 1024;
    int one = 1;
#ifdef _WIN32
    setsockopt(s, SOL_SOCKET, SO_RCVBUF,
               reinterpret_cast<const char*>(&buffer_size), sizeof(buffer_size));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF,
               reinterpret_cast<const char*>(&buffer_size), sizeof(buffer_size));
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char*>(&one), sizeof(one));
#else
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
#  ifdef SO_NOSIGPIPE
    setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#  endif
#endif
}
int poll_many(pollfd_t* fds, size_t count, int timeout_ms) {
#ifdef _WIN32
    return WSAPoll(fds, static_cast<ULONG>(count), timeout_ms);
#else
    return ::poll(fds, static_cast<nfds_t>(count), timeout_ms);
#endif
}
bool wait_socket(socket_t s, short events,
                 std::chrono::steady_clock::time_point deadline) {
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return false;
        auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        if (remain <= 0) remain = 1;
        pollfd_t pfd{};
        pfd.fd = s;
        pfd.events = events;
        const int rc = poll_many(&pfd, 1, static_cast<int>(std::min<int64_t>(remain, INT32_MAX)));
        if (rc > 0) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return false;
            return (pfd.revents & events) != 0;
        }
        if (rc == 0) return false;
        if (interrupted_error(sockerr())) continue;
        return false;
    }
}
bool connect_with_deadline(socket_t s, const sockaddr* addr, socket_len_t addrlen,
                           std::chrono::steady_clock::time_point deadline) {
    nonblocking(s);
#ifdef _WIN32
    const int rc = ::connect(s, addr, static_cast<int>(addrlen));
#else
    const int rc = ::connect(s, addr, addrlen);
#endif
    if (rc == 0) return true;
    const int e = sockerr();
#ifdef _WIN32
    if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS && e != WSAEALREADY && e != WSAEINTR)
        return false;
#else
    if (e != EINPROGRESS && e != EALREADY && e != EINTR && e != EWOULDBLOCK)
        return false;
#endif
    if (!wait_socket(s, POLLOUT, deadline)) return false;
    int so_error = 0;
#ifdef _WIN32
    int opt_len = sizeof(so_error);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR,
                   reinterpret_cast<char*>(&so_error), &opt_len) != 0)
        return false;
#else
    socklen_t opt_len = sizeof(so_error);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &so_error, &opt_len) != 0)
        return false;
#endif
    return so_error == 0;
}
void random_fill(uint8_t* p, size_t n) {
#ifdef _WIN32
    if (n > static_cast<size_t>(ULONG_MAX) ||
        BCryptGenRandom(nullptr, p, static_cast<ULONG>(n),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw std::runtime_error("BCryptGenRandom failed");
#elif defined(__linux__)
    size_t done = 0;
    while (done < n) {
        const ssize_t got = ::getrandom(p + done, n - done, 0);
        if (got > 0) {
            done += static_cast<size_t>(got);
            continue;
        }
        if (got < 0 && errno == EINTR) continue;
        break;
    }
    if (done == n) return;
    const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw std::runtime_error("cannot open /dev/urandom");
    while (done < n) {
        const ssize_t got = ::read(fd, p + done, n - done);
        if (got > 0) done += static_cast<size_t>(got);
        else if (got < 0 && errno == EINTR) continue;
        else {
            ::close(fd);
            throw std::runtime_error("random source failed");
        }
    }
    ::close(fd);
#else
    const int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd < 0) throw std::runtime_error("cannot open /dev/urandom");
    size_t done = 0;
    while (done < n) {
        const ssize_t got = ::read(fd, p + done, n - done);
        if (got > 0) done += static_cast<size_t>(got);
        else if (got < 0 && errno == EINTR) continue;
        else {
            ::close(fd);
            throw std::runtime_error("random source failed");
        }
    }
    ::close(fd);
#endif
}
std::string random_bytes(size_t n) {
    std::string out(n, '\0');
    random_fill(reinterpret_cast<uint8_t*>(out.data()), n);
    return out;
}
std::string as_string(const py::bytes& b) { return static_cast<std::string>(b); }
py::bytes as_bytes(const std::string& s) { return py::bytes(s.data(), s.size()); }
uint16_t u16(const uint8_t* p) {
    return static_cast<uint16_t>((uint16_t(p[0]) << 8) | uint16_t(p[1]));
}
uint32_t u32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
std::optional<size_t> find_bytes(const std::vector<uint8_t>& bytes,
                                 const std::string& marker, size_t start = 0) {
    if (marker.empty() || bytes.size() < marker.size() ||
        start > bytes.size() - marker.size())
        return {};
    const uint8_t* cur = bytes.data() + start;
    const uint8_t* last = bytes.data() + bytes.size() - marker.size();
    while (cur <= last) {
        const void* hit = std::memchr(cur, static_cast<unsigned char>(marker[0]),
                                      static_cast<size_t>(last - cur + 1));
        if (!hit) return {};
        cur = static_cast<const uint8_t*>(hit);
        if (std::memcmp(cur, marker.data(), marker.size()) == 0)
            return static_cast<size_t>(cur - bytes.data());
        ++cur;
    }
    return {};
}
std::optional<double> timeout_arg(const py::object& o) {
    if (o.is_none()) return {};
    const double value = py::cast<double>(o);
    if (!std::isfinite(value) || value < 0.0 || value > 365.0 * 24.0 * 3600.0)
        throw py::value_error("timeout must be finite, between 0 and 365 days, or None");
    return value;
}
std::optional<std::string> eid_arg(const py::object& o) {
    if (o.is_none()) return {};
    std::string e = as_string(py::cast<py::bytes>(o));
    if (e.size() != EID_N) throw py::value_error("eid must be 8 bytes");
    return e;
}
class Quota {
public:
    explicit Quota(size_t limit) : limit_(limit) {}
    bool acquire(size_t n) {
        if (n == 0) return true;
        if (n > limit_) return false;
        size_t current = used_.load(std::memory_order_relaxed);
        for (;;) {
            if (current > limit_ - n) return false;
            if (used_.compare_exchange_weak(current, current + n,
                                            std::memory_order_acq_rel,
                                            std::memory_order_relaxed))
                return true;
        }
    }
    void release(size_t n) {
        if (n) used_.fetch_sub(n, std::memory_order_acq_rel);
    }
private:
    const size_t limit_;
    std::atomic<size_t> used_{0};
};
class Lease {
public:
    static std::shared_ptr<Lease> make(const std::shared_ptr<Quota>& global,
                                       const std::shared_ptr<Quota>& local,
                                       size_t bytes) {
        if (!global || !local) return {};
        if (!global->acquire(bytes)) return {};
        if (!local->acquire(bytes)) {
            global->release(bytes);
            return {};
        }
        try {
            return std::shared_ptr<Lease>(new Lease(global, local, bytes));
        } catch (...) {
            local->release(bytes);
            global->release(bytes);
            throw;
        }
    }
    ~Lease() {
        if (local_) local_->release(bytes_);
        if (global_) global_->release(bytes_);
    }
    Lease(const Lease&) = delete;
    Lease& operator=(const Lease&) = delete;
private:
    Lease(std::shared_ptr<Quota> global, std::shared_ptr<Quota> local, size_t bytes)
        : global_(std::move(global)), local_(std::move(local)), bytes_(bytes) {}
    std::shared_ptr<Quota> global_;
    std::shared_ptr<Quota> local_;
    size_t bytes_;
};
struct Message {
    std::string eid;
    std::string payload;
    bool authed = false;
    std::shared_ptr<Lease> memory;
};
struct Pending {
    std::string payload;
    std::string eid;
    bool authed = false;
    std::shared_ptr<Lease> memory;
};
struct Conn {
    socket_t sock = BAD_SOCKET;
    bool server_side = false;
    std::atomic<bool> authed{false};
    std::atomic<bool> closed{false};
    std::atomic<bool> backpressure{false};
    std::atomic<bool> handshake_started{false};
    std::string temp_cid;
    std::string cid;
    std::string magic1;
    std::string magic2;
    std::string peer;
    std::chrono::steady_clock::time_point connect_time = std::chrono::steady_clock::now();
    uint64_t connection_id = 0;
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<Message> recvq;
    std::deque<Pending> sendq;
    std::map<std::string, std::chrono::steady_clock::time_point> eid_activity;
    std::chrono::steady_clock::time_point last_cleanup = std::chrono::steady_clock::now();
    std::vector<uint8_t> input;
    std::shared_ptr<Lease> input_memory;
    std::shared_ptr<Lease> input_extra_memory;
    std::vector<uint8_t> wire;
    size_t wire_off = 0;
    std::shared_ptr<Lease> wire_memory;
    std::shared_ptr<Quota> global_memory;
    std::shared_ptr<Quota> local_memory = std::make_shared<Quota>(MAX_CONNECTION_BUFFERED_BYTES);
    explicit Conn(std::shared_ptr<Quota> global) : global_memory(std::move(global)) {}
};
void log_callback_error(const char* where, const char* what) {
    static std::mutex log_mutex;
    static auto last_log = std::chrono::steady_clock::time_point::min();
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(log_mutex);
    if (last_log == std::chrono::steady_clock::time_point::min() ||
        now - last_log >= std::chrono::seconds(5)) {
        last_log = now;
        std::cerr << '[' << where << "] callback error: " << what << '\n';
    }
}
class Pool {
    struct State {
        explicit State(size_t limit) : pending_limit(limit) {}
        std::mutex mutex;
        std::condition_variable cv;
        std::deque<std::function<void()>> queue;
        bool stopped = false;
        size_t pending_limit;
    };
public:
    explicit Pool(size_t n) : n_(n), state_(std::make_shared<State>(pending_limit_for(n))) {
        if (n == 0) throw std::invalid_argument("concurrency limit must be >= 1");
        if (n > MAX_POOL_WORKERS)
            throw std::invalid_argument("concurrency limit must be <= 64");
    }
    ~Pool() { stop(); }
    bool submit(std::function<void()> fn) {
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            if (state_->stopped || state_->queue.size() >= state_->pending_limit)
                return false;
            state_->queue.push_back(std::move(fn));
        }
        try {
            ensure_workers();
        } catch (...) {
            stop();
            throw;
        }
        state_->cv.notify_one();
        return true;
    }
    void stop() {
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            if (state_->stopped) {
            } else {
                state_->stopped = true;
                state_->queue.clear();
            }
        }
        state_->cv.notify_all();
        std::lock_guard<std::mutex> workers_lock(workers_mutex_);
        const auto self = std::this_thread::get_id();
        for (auto& worker : workers_) {
            if (!worker.joinable()) continue;
            if (worker.get_id() == self) worker.detach();
            else worker.join();
        }
        workers_.clear();
    }
private:
    static size_t pending_limit_for(size_t n) {
        if (n > MAX_PENDING_CALLBACKS_MAX / 64)
            return MAX_PENDING_CALLBACKS_MAX;
        return std::max(MAX_PENDING_CALLBACKS_MIN,
                        std::min(MAX_PENDING_CALLBACKS_MAX, n * 64));
    }
    void ensure_workers() {
        std::lock_guard<std::mutex> lock(workers_mutex_);
        while (workers_.size() < n_) {
            auto state = state_;
            workers_.emplace_back([state] { worker_loop(std::move(state)); });
        }
    }
    static void worker_loop(std::shared_ptr<State> state) {
        for (;;) {
            std::function<void()> fn;
            {
                std::unique_lock<std::mutex> lock(state->mutex);
                state->cv.wait(lock, [&] { return state->stopped || !state->queue.empty(); });
                if (state->stopped && state->queue.empty()) return;
                fn = std::move(state->queue.front());
                state->queue.pop_front();
            }
            try {
                fn();
            } catch (const std::exception& e) {
                log_callback_error("backing", e.what());
            } catch (...) {
                log_callback_error("backing", "unknown exception");
            }
        }
    }
    size_t n_;
    std::shared_ptr<State> state_;
    std::mutex workers_mutex_;
    std::vector<std::thread> workers_;
};
std::vector<uint8_t> make_frame(const Conn& c, const Pending& p) {
    const size_t payload_size = p.payload.size();
    if (!p.authed && payload_size > MAX_UNAUTH)
        throw std::length_error("handshake payload exceeds 65535 bytes");
    if (p.authed && payload_size > MAX_AUTH)
        throw std::length_error("payload exceeds 25-bit length limit");
    const size_t header_size = p.authed ? AUTH_HEAD + EID_N : UNAUTH_HEAD;
    const size_t total_size = MAGIC_N + header_size + payload_size + MAGIC_N;
    std::vector<uint8_t> out(total_size);
    uint8_t* ptr = out.data();
    std::memcpy(ptr, c.magic1.data(), MAGIC_N);
    ptr += MAGIC_N;
    if (!p.authed) {
        ptr[0] = static_cast<uint8_t>(payload_size >> 8);
        ptr[1] = static_cast<uint8_t>(payload_size & 0xff);
        ptr += UNAUTH_HEAD;
    } else {
        ptr[0] = static_cast<uint8_t>(payload_size >> 24);
        ptr[1] = static_cast<uint8_t>((payload_size >> 16) & 0xff);
        ptr[2] = static_cast<uint8_t>((payload_size >> 8) & 0xff);
        ptr[3] = static_cast<uint8_t>(payload_size & 0xff);
        ptr[4] = '0';
        std::memcpy(ptr + AUTH_HEAD, p.eid.data(), EID_N);
        ptr += AUTH_HEAD + EID_N;
    }
    if (payload_size) std::memcpy(ptr, p.payload.data(), payload_size);
    ptr += payload_size;
    std::memcpy(ptr, c.magic2.data(), MAGIC_N);
    return out;
}
bool has_recv_room(const std::shared_ptr<Conn>& c) {
    std::lock_guard<std::mutex> lock(c->mutex);
    return !c->closed && c->recvq.size() < QUEUE_LIMIT;
}
bool reallocate_input(Conn& c, size_t target_capacity) {
    if (target_capacity > MAX_INPUT_BUFFER) return false;
    if (target_capacity < c.input.size()) target_capacity = c.input.size();
    if (target_capacity == c.input.capacity()) return true;
    auto new_lease = Lease::make(c.global_memory, c.local_memory, target_capacity);
    if (!new_lease) return false;
    std::vector<uint8_t> replacement;
    try {
        replacement.reserve(target_capacity);
        replacement.insert(replacement.end(), c.input.begin(), c.input.end());
    } catch (...) {
        return false;
    }
    std::shared_ptr<Lease> extra_lease;
    if (replacement.capacity() > target_capacity) {
        extra_lease = Lease::make(c.global_memory, c.local_memory,
                                  replacement.capacity() - target_capacity);
        if (!extra_lease) return false;
    }
    auto old_lease = std::move(c.input_memory);
    auto old_extra_lease = std::move(c.input_extra_memory);
    std::vector<uint8_t> old_buffer;
    old_buffer.swap(c.input);
    c.input.swap(replacement);
    std::vector<uint8_t>().swap(old_buffer);
    old_lease.reset();
    old_extra_lease.reset();
    c.input_memory = std::move(new_lease);
    c.input_extra_memory = std::move(extra_lease);
    return true;
}
bool ensure_input_capacity(Conn& c, size_t required) {
    if (required > MAX_INPUT_BUFFER) return false;
    if (required <= c.input.capacity()) return true;
    size_t target = std::max<size_t>(4096, c.input.capacity());
    while (target < required) {
        const size_t next = (target > MAX_INPUT_BUFFER / 2) ? MAX_INPUT_BUFFER : target * 2;
        if (next <= target) return false;
        target = next;
    }
    return reallocate_input(c, target);
}
void compact_input(Conn& c, size_t consumed) {
    if (consumed) {
        if (consumed >= c.input.size()) c.input.clear();
        else c.input.erase(c.input.begin(), c.input.begin() + static_cast<ptrdiff_t>(consumed));
    }
    if (c.input.empty() && c.input.capacity() > 256 * 1024) {
        std::vector<uint8_t>().swap(c.input);
        c.input_memory.reset();
        c.input_extra_memory.reset();
        return;
    }
    if (c.input.capacity() > 1024 * 1024 &&
        c.input.size() < c.input.capacity() / 8) {
        const size_t target = std::max<size_t>(4096, c.input.size() * 2);
        if (target < c.input.capacity()) reallocate_input(c, target);
    }
}
enum class EidResult { Fresh, Existing, Limit, Closed };
EidResult touch_eid(const std::shared_ptr<Conn>& c, const std::string& eid) {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(c->mutex);
    if (c->closed) return EidResult::Closed;
    auto found = c->eid_activity.find(eid);
    if (found != c->eid_activity.end()) {
        found->second = now;
        return EidResult::Existing;
    }
    for (auto it = c->eid_activity.begin(); it != c->eid_activity.end();) {
        if (now - it->second >= EID_TTL) it = c->eid_activity.erase(it);
        else ++it;
    }
    if (c->eid_activity.size() >= MAX_ACTIVE_EIDS_PER_CONNECTION)
        return EidResult::Limit;
    c->eid_activity.emplace(eid, now);
    return EidResult::Fresh;
}
void clear_conn_io_state(const std::shared_ptr<Conn>& c) {
    c->closed = true;
    if (c->sock != BAD_SOCKET) {
        close_sock(c->sock);
        c->sock = BAD_SOCKET;
    }
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        c->recvq.clear();
        c->sendq.clear();
        c->eid_activity.clear();
    }
    std::vector<uint8_t>().swap(c->wire);
    c->wire_off = 0;
    c->wire_memory.reset();
    std::vector<uint8_t>().swap(c->input);
    c->input_memory.reset();
    c->input_extra_memory.reset();
    c->cv.notify_all();
}
bool resync_after_malformed(Conn& c, size_t& off) {
    const auto next = find_bytes(c.input, c.magic1, off + 1);
    if (next) {
        off = *next;
        return true;
    }
    size_t keep = std::min(c.input.size(), MAGIC_N - 1);
    while (keep > 0 &&
           std::memcmp(c.input.data() + c.input.size() - keep,
                       c.magic1.data(), keep) != 0)
        --keep;
    off = c.input.size() - keep;
    return false;
}
template <class Deliver>
bool parse_buffered(const std::shared_ptr<Conn>& conn, Deliver deliver) {
    Conn& c = *conn;
    bool progressed = false;
    size_t off = 0;
    size_t frames = 0;
    size_t parse_steps = 0;
    while (!c.closed && frames < MAX_PARSE_FRAMES_PER_CALL &&
           parse_steps < MAX_PARSE_STEPS_PER_CALL) {
        ++parse_steps;
        if (off >= c.input.size()) break;
        if (!has_recv_room(conn)) break;
        const auto start = find_bytes(c.input, c.magic1, off);
        if (!start) {
            const size_t remaining = c.input.size() - off;
            size_t keep = std::min(remaining, MAGIC_N - 1);
            while (keep > 0 &&
                   std::memcmp(c.input.data() + c.input.size() - keep,
                               c.magic1.data(), keep) != 0)
                --keep;
            const size_t new_off = c.input.size() - keep;
            if (new_off > off) progressed = true;
            off = new_off;
            break;
        }
        if (*start > off) {
            off = *start;
            progressed = true;
        }
        const bool authed = c.authed.load(std::memory_order_acquire);
        const size_t header_size = authed ? AUTH_HEAD + EID_N : UNAUTH_HEAD;
        const size_t body_size = MAGIC_N + header_size;
        if (c.input.size() - off < body_size) break;
        const uint8_t* base = c.input.data() + off;
        const uint32_t payload_size = authed ? u32(base + MAGIC_N) : u16(base + MAGIC_N);
        std::string eid;
        if (authed) {
            const uint8_t flag = base[MAGIC_N + 4];
            if (flag != '0' && flag != '1') {
                progressed = true;
                if (!resync_after_malformed(c, off)) break;
                continue;
            }
            eid.assign(reinterpret_cast<const char*>(base + MAGIC_N + AUTH_HEAD), EID_N);
        }
        if (payload_size > (authed ? MAX_AUTH : MAX_UNAUTH)) {
            progressed = true;
            if (!resync_after_malformed(c, off)) break;
            continue;
        }
        const size_t total_size = body_size + static_cast<size_t>(payload_size) + MAGIC_N;
        if (c.input.size() - off < total_size) break;
        if (std::memcmp(c.input.data() + off + total_size - MAGIC_N,
                        c.magic2.data(), MAGIC_N) != 0) {
            const auto nested = find_bytes(c.input, c.magic1, off + MAGIC_N);
            if (nested && *nested < off + total_size) {
                off = *nested;
            } else {
                off += total_size;
            }
            ++frames;
            progressed = true;
            continue;
        }
        auto memory = Lease::make(c.global_memory, c.local_memory,
                                  static_cast<size_t>(payload_size) + sizeof(Message) + 32);
        if (!memory) {
            off += total_size;
            ++frames;
            progressed = true;
            continue;
        }
        std::string payload;
        try {
            payload.assign(reinterpret_cast<const char*>(c.input.data() + off + body_size),
                           static_cast<size_t>(payload_size));
        } catch (const std::bad_alloc&) {
            off += total_size;
            ++frames;
            progressed = true;
            continue;
        }
        if (!deliver(authed, eid, std::move(payload), std::move(memory))) {
            compact_input(c, off);
            return progressed;
        }
        off += total_size;
        ++frames;
        progressed = true;
    }
    compact_input(c, off);
    return progressed;
}
class Server {
public:
    Server(std::string host, uint16_t port, py::object handshake_worker,
           py::object on_exchange, size_t simultaneous_handshakes,
           size_t simultaneous_exchanges)
        : host_(std::move(host)),
          port_(port),
          handshake_worker_(std::move(handshake_worker)),
          on_exchange_(std::move(on_exchange)),
          has_handshake_worker_(!handshake_worker_.is_none()),
          has_on_exchange_(!on_exchange_.is_none()),
          global_memory_(std::make_shared<Quota>(MAX_GLOBAL_BUFFERED_BYTES)),
          handshakes_(simultaneous_handshakes),
          exchanges_(simultaneous_exchanges) {
        init_sockets();
        magic1_ = random_bytes(MAGIC_N);
        do {
            magic2_ = random_bytes(MAGIC_N);
        } while (magic1_ == magic2_);
    }
    ~Server() {
        if (PyGILState_Check()) {
            py::gil_scoped_release release;
            stop();
        } else {
            stop();
        }
    }
    void start() {
        if (stopping_.load()) throw std::runtime_error("server has been stopped");
        if (running_.load()) throw std::runtime_error("already running");
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        addrinfo* results = nullptr;
        const std::string service = std::to_string(port_);
        const int rc = getaddrinfo(host_.empty() ? nullptr : host_.c_str(),
                                   service.c_str(), &hints, &results);
        if (rc != 0) throw std::runtime_error("getaddrinfo failed");
        socket_t listener = BAD_SOCKET;
        for (addrinfo* item = results; item; item = item->ai_next) {
            listener = ::socket(item->ai_family, item->ai_socktype, item->ai_protocol);
            if (listener == BAD_SOCKET) continue;
            int one = 1;
#ifdef _WIN32
            setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&one), sizeof(one));
#else
            setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
            if (::bind(listener, item->ai_addr,
#ifdef _WIN32
                       static_cast<int>(item->ai_addrlen)
#else
                       static_cast<socklen_t>(item->ai_addrlen)
#endif
                       ) == 0 && ::listen(listener, SOMAXCONN) == 0) {
                break;
            }
            close_sock(listener);
            listener = BAD_SOCKET;
        }
        freeaddrinfo(results);
        if (listener == BAD_SOCKET) throw std::runtime_error("could not bind/listen");
        try {
            nonblocking(listener);
        } catch (...) {
            close_sock(listener);
            throw;
        }
        listener_ = listener;
        running_ = true;
        try {
            io_thread_ = std::thread([this] { io_loop(); });
        } catch (...) {
            running_ = false;
            close_sock(listener_);
            listener_ = BAD_SOCKET;
            throw;
        }
    }
    void stop() {
        if (stopping_.exchange(true)) return;
        running_ = false;
        if (io_thread_.joinable() && io_thread_.get_id() != std::this_thread::get_id())
            io_thread_.join();
        if (listener_ != BAD_SOCKET) {
            close_sock(listener_);
            listener_ = BAD_SOCKET;
        }
        std::vector<std::shared_ptr<Conn>> remaining;
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            remaining.swap(connections_);
        }
        for (const auto& conn : remaining) clear_conn_io_state(conn);
        {
            std::lock_guard<std::mutex> lock(ids_mutex_);
            ids_.clear();
            temporary_ids_.clear();
        }
        peer_counts_.clear();
        peer_accepts_.clear();
        handshakes_.stop();
        exchanges_.stop();
    }
    py::bytes MAGIC1() const { return as_bytes(magic1_); }
    py::bytes MAGIC2() const { return as_bytes(magic2_); }
    bool is_authed(py::bytes cid) {
        auto conn = find(as_string(cid));
        return conn && conn->authed.load(std::memory_order_acquire);
    }
    void set_backpressure(py::bytes cid, bool value) {
        auto conn = find(as_string(cid));
        if (!conn) throw py::key_error("unknown cid");
        conn->backpressure = value;
    }
    void close_client(py::bytes cid) {
        const std::string id = as_string(cid);
        std::shared_ptr<Conn> conn;
        {
            std::lock_guard<std::mutex> lock(ids_mutex_);
            auto it = ids_.find(id);
            if (it == ids_.end()) throw py::key_error("unknown cid");
            conn = it->second;
            ids_.erase(it);
            conn->closed = true;
        }
        conn->cv.notify_all();
    }
    py::object send(py::bytes payload_bytes, py::bytes cid_bytes, py::object eid_obj) {
        auto conn = find(as_string(cid_bytes));
        if (!conn) throw py::key_error("unknown cid");
        if (!conn->authed.load(std::memory_order_acquire))
            throw std::runtime_error(
                "normal send is unavailable before authentication; use send_handshake(temp_cid, data)");
        const std::string payload = as_string(payload_bytes);
        auto requested_eid = eid_arg(eid_obj);
        std::string eid;
        if (requested_eid) {
            eid = *requested_eid;
            const EidResult result = touch_eid(conn, eid);
            if (result == EidResult::Limit)
                throw py::value_error("too many active eids for this connection");
            if (result == EidResult::Closed)
                throw std::runtime_error("connection closed");
        } else {
            bool generated = false;
            for (int tries = 0; tries < 16; ++tries) {
                eid = random_bytes(EID_N);
                const EidResult result = touch_eid(conn, eid);
                if (result == EidResult::Fresh) {
                    generated = true;
                    break;
                }
                if (result == EidResult::Limit)
                    throw py::value_error("too many active eids for this connection");
                if (result == EidResult::Closed)
                    throw std::runtime_error("connection closed");
            }
            if (!generated) throw std::runtime_error("could not generate a unique eid");
        }
        enqueue(conn, Pending{payload, eid, true, {}});
        return py::object(as_bytes(eid));
    }
    void send_handshake(py::bytes temp_cid, py::bytes payload_bytes) {
        auto conn = find_temp(as_string(temp_cid));
        if (!conn) throw py::key_error("unknown temp_cid");
        if (conn->authed.load(std::memory_order_acquire))
            throw std::runtime_error("handshake send only allowed before auth");
        enqueue(conn, Pending{as_string(payload_bytes), {}, false, {}});
    }
    py::object recv(py::bytes cid_bytes, py::object eid_obj, py::object timeout_obj) {
        auto conn = find(as_string(cid_bytes));
        if (!conn) throw py::key_error("unknown cid");
        if (!conn->authed.load(std::memory_order_acquire))
            throw std::runtime_error(
                "normal recv is unavailable before authentication; use recv_handshake(temp_cid)");
        auto eid = eid_arg(eid_obj);
        if (!eid) throw py::value_error("eid is required for authenticated recv");
        return pop(conn, eid, true, timeout_arg(timeout_obj));
    }
    py::object recv_handshake(py::bytes temp_cid, py::object timeout_obj) {
        auto conn = find_temp(as_string(temp_cid));
        if (!conn) throw py::key_error("unknown temp_cid");
        if (conn->authed.load(std::memory_order_acquire))
            throw std::runtime_error("handshake recv only allowed before auth");
        return pop(conn, {}, false, timeout_arg(timeout_obj));
    }
    bool auth_finished(py::bytes temp_cid, py::bytes new_cid_bytes,
                       py::object confirmation_payload) {
        const std::string temp = as_string(temp_cid);
        std::string new_id = as_string(new_cid_bytes);
        if (new_id.empty()) throw py::value_error("new_cid must not be empty");
        if (new_id.size() > MAX_CID_BYTES)
            throw py::value_error("new_cid exceeds the 256-byte limit");
        std::lock_guard<std::mutex> lock(ids_mutex_);
        auto temp_it = temporary_ids_.find(temp);
        if (temp_it == temporary_ids_.end()) throw py::key_error("unknown temp_cid");
        auto conn = temp_it->second;
        if (conn->closed) throw std::runtime_error("connection closed");
        if (ids_.count(new_id)) throw py::value_error("new_cid already in use");
        if (!confirmation_payload.is_none()) {
            enqueue(conn, Pending{as_string(py::cast<py::bytes>(confirmation_payload)), {}, false, {}});
        }
        std::string conn_id_copy = new_id;
        ids_.emplace(new_id, conn);
        conn->cid = std::move(conn_id_copy);
        conn->authed.store(true, std::memory_order_release);
        temporary_ids_.erase(temp_it);
        conn->cv.notify_all();
        return true;
    }
private:
    static py::object pop(const std::shared_ptr<Conn>& conn,
                          const std::optional<std::string>& eid,
                          bool want_authed, const std::optional<double>& timeout) {
        std::unique_lock<std::mutex> lock(conn->mutex);
        auto predicate = [&] {
            if (conn->closed || conn->authed.load(std::memory_order_acquire) != want_authed)
                return true;
            return std::any_of(conn->recvq.begin(), conn->recvq.end(), [&](const Message& message) {
                return message.authed == want_authed && (!want_authed || message.eid == *eid);
            });
        };
        bool ready = false;
        {
            py::gil_scoped_release release;
            if (timeout) {
                ready = conn->cv.wait_for(lock, std::chrono::duration<double>(*timeout), predicate);
            } else {
                conn->cv.wait(lock, predicate);
                ready = true;
            }
        }
        if (!ready) {
            lock.unlock();
            return py::none();
        }
        auto it = std::find_if(conn->recvq.begin(), conn->recvq.end(), [&](const Message& message) {
            return message.authed == want_authed && (!want_authed || message.eid == *eid);
        });
        if (it == conn->recvq.end()) {
            lock.unlock();
            return py::none();
        }
        std::string payload = std::move(it->payload);
        conn->recvq.erase(it);
        lock.unlock();
        return py::object(as_bytes(payload));
    }
    std::shared_ptr<Conn> find(const std::string& id) {
        std::lock_guard<std::mutex> lock(ids_mutex_);
        auto it = ids_.find(id);
        return it == ids_.end() ? nullptr : it->second;
    }
    std::shared_ptr<Conn> find_temp(const std::string& id) {
        std::lock_guard<std::mutex> lock(ids_mutex_);
        auto it = temporary_ids_.find(id);
        return it == temporary_ids_.end() ? nullptr : it->second;
    }
    void enqueue(const std::shared_ptr<Conn>& conn, Pending pending) {
        const size_t max_payload = pending.authed ? MAX_AUTH : MAX_UNAUTH;
        if (pending.payload.size() > max_payload) {
            if (pending.authed) throw py::value_error("payload exceeds 25-bit length limit");
            throw py::value_error("handshake payload exceeds 65535 bytes");
        }
        std::lock_guard<std::mutex> lock(conn->mutex);
        if (conn->closed) throw std::runtime_error("connection closed");
        if (conn->sendq.size() >= QUEUE_LIMIT)
            throw py::value_error("send queue full (maximum 8)");
        pending.memory = Lease::make(conn->global_memory, conn->local_memory,
                                     pending.payload.size() + sizeof(Pending) + 32);
        if (!pending.memory) throw py::value_error("buffer budget exhausted");
        conn->sendq.push_back(std::move(pending));
    }
    static std::string peer_address(const sockaddr_storage& address) {
        char out[INET6_ADDRSTRLEN]{};
        if (address.ss_family == AF_INET) {
            const auto* a = reinterpret_cast<const sockaddr_in*>(&address);
            if (inet_ntop(AF_INET, &a->sin_addr, out, sizeof(out))) return out;
        } else if (address.ss_family == AF_INET6) {
            const auto* a = reinterpret_cast<const sockaddr_in6*>(&address);
            if (inet_ntop(AF_INET6, &a->sin6_addr, out, sizeof(out))) return out;
        }
        return "unknown";
    }
    void prune_peer_buckets(std::chrono::steady_clock::time_point now, bool force = false) {
        if (!force && now - last_peer_cleanup_ < std::chrono::seconds(10) &&
            peer_accepts_.size() < MAX_PEER_BUCKETS)
            return;
        last_peer_cleanup_ = now;
        for (auto it = peer_accepts_.begin(); it != peer_accepts_.end();) {
            auto& times = it->second;
            while (!times.empty() && now - times.front() >= std::chrono::minutes(1))
                times.pop_front();
            const bool active = peer_counts_.find(it->first) != peer_counts_.end();
            if (times.empty() && !active) it = peer_accepts_.erase(it);
            else ++it;
        }
    }
    bool allow_peer(const std::string& peer) {
        const auto now = std::chrono::steady_clock::now();
        prune_peer_buckets(now);
        auto active = peer_counts_.find(peer);
        if (active != peer_counts_.end() && active->second >= MAX_CONNECTIONS_PER_PEER)
            return false;
        auto bucket = peer_accepts_.find(peer);
        if (bucket == peer_accepts_.end()) {
            if (peer_accepts_.size() >= MAX_PEER_BUCKETS) {
                prune_peer_buckets(now, true);
                if (peer_accepts_.size() >= MAX_PEER_BUCKETS) return false;
            }
            bucket = peer_accepts_.emplace(peer, std::deque<std::chrono::steady_clock::time_point>{}).first;
        }
        auto& times = bucket->second;
        while (!times.empty() && now - times.front() >= std::chrono::minutes(1))
            times.pop_front();
        if (times.size() >= MAX_NEW_CONNECTIONS_PER_PEER_PER_MINUTE) return false;
        times.push_back(now);
        return true;
    }
    void accept_ready() {
        for (size_t accepted = 0; accepted < MAX_ACCEPT_PER_TICK; ++accepted) {
            sockaddr_storage address{};
#ifdef _WIN32
            int address_len = sizeof(address);
#else
            socklen_t address_len = sizeof(address);
#endif
            const socket_t sock = ::accept(listener_, reinterpret_cast<sockaddr*>(&address), &address_len);
            if (sock == BAD_SOCKET) {
                if (would_block(sockerr())) break;
                break;
            }
            size_t connection_count = 0;
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                connection_count = connections_.size();
            }
            size_t unauth_count = 0;
            {
                std::lock_guard<std::mutex> lock(ids_mutex_);
                unauth_count = temporary_ids_.size();
            }
            const std::string peer = peer_address(address);
            bool peer_ok = false;
            try {
                peer_ok = allow_peer(peer);
            } catch (...) {
                close_sock(sock);
                continue;
            }
            if (connection_count >= MAX_CONNECTIONS ||
                unauth_count >= MAX_UNAUTH_CONNECTIONS || !peer_ok) {
                close_sock(sock);
                continue;
            }
            std::shared_ptr<Conn> conn;
            bool temp_inserted = false;
            try {
                tune_socket(sock);
                nonblocking(sock);
                conn = std::make_shared<Conn>(global_memory_);
                conn->sock = sock;
                conn->server_side = true;
                conn->magic1 = magic1_;
                conn->magic2 = magic2_;
                conn->peer = peer;
                conn->connect_time = std::chrono::steady_clock::now();
                conn->connection_id = next_connection_id_++;
                conn->wire_memory = Lease::make(conn->global_memory, conn->local_memory, 16);
                if (!conn->wire_memory) throw std::runtime_error("global buffer budget exhausted");
                conn->wire.reserve(16);
                conn->wire.insert(conn->wire.end(), magic1_.begin(), magic1_.end());
                conn->wire.insert(conn->wire.end(), magic2_.begin(), magic2_.end());
                {
                    std::lock_guard<std::mutex> lock(ids_mutex_);
                    do {
                        conn->temp_cid = random_bytes(EID_N);
                    } while (temporary_ids_.count(conn->temp_cid) || ids_.count(conn->temp_cid));
                    temporary_ids_.emplace(conn->temp_cid, conn);
                    temp_inserted = true;
                }
                {
                    std::lock_guard<std::mutex> lock(connections_mutex_);
                    connections_.push_back(conn);
                }
                ++peer_counts_[peer];
            } catch (...) {
                if (temp_inserted) {
                    std::lock_guard<std::mutex> lock(ids_mutex_);
                    temporary_ids_.erase(conn->temp_cid);
                }
                if (conn) clear_conn_io_state(conn);
                else close_sock(sock);
            }
        }
    }
    void cleanup_exchanges(const std::shared_ptr<Conn>& conn) {
        const auto now = std::chrono::steady_clock::now();
        if (now - conn->last_cleanup < CLEANUP_INTERVAL) return;
        conn->last_cleanup = now;
        std::vector<std::string> expired;
        {
            std::lock_guard<std::mutex> lock(conn->mutex);
            for (auto it = conn->eid_activity.begin(); it != conn->eid_activity.end();) {
                if (now - it->second >= EID_TTL) {
                    expired.push_back(it->first);
                    it = conn->eid_activity.erase(it);
                } else {
                    ++it;
                }
            }
            if (!expired.empty()) {
                auto is_expired = [&](const std::string& eid) {
                    return std::binary_search(expired.begin(), expired.end(), eid);
                };
                conn->recvq.erase(std::remove_if(conn->recvq.begin(), conn->recvq.end(),
                    [&](const Message& message) { return message.authed && is_expired(message.eid); }),
                    conn->recvq.end());
                conn->sendq.erase(std::remove_if(conn->sendq.begin(), conn->sendq.end(),
                    [&](const Pending& pending) { return pending.authed && is_expired(pending.eid); }),
                    conn->sendq.end());
                conn->cv.notify_all();
            }
        }
    }
    bool deliver_message(const std::shared_ptr<Conn>& conn, bool authed,
                         const std::string& eid, std::string payload,
                         std::shared_ptr<Lease> memory, uint64_t connection_id) {
        bool fresh_eid = false;
        try {
            std::lock_guard<std::mutex> lock(conn->mutex);
            if (conn->closed || conn->recvq.size() >= QUEUE_LIMIT) return false;
            if (authed) {
                const auto now = std::chrono::steady_clock::now();
                auto it = conn->eid_activity.find(eid);
                if (it != conn->eid_activity.end()) {
                    it->second = now;
                } else {
                    for (auto old = conn->eid_activity.begin(); old != conn->eid_activity.end();) {
                        if (now - old->second >= EID_TTL) old = conn->eid_activity.erase(old);
                        else ++old;
                    }
                    if (conn->eid_activity.size() >= MAX_ACTIVE_EIDS_PER_CONNECTION) {
                        conn->closed = true;
                        conn->cv.notify_all();
                        return false;
                    }
                    conn->eid_activity.emplace(eid, now);
                    fresh_eid = true;
                }
            }
            conn->recvq.push_back(Message{eid, std::move(payload), authed, std::move(memory)});
            conn->cv.notify_all();
        } catch (...) {
            conn->closed = true;
            conn->cv.notify_all();
            return false;
        }
        if (!authed && conn->server_side && !conn->handshake_started.exchange(true) &&
            has_handshake_worker_) {
            const std::string temp = conn->temp_cid;
            try {
                handshakes_.submit([this, temp, connection_id] {
                    auto current = find_temp(temp);
                    if (!current || current->closed || current->connection_id != connection_id)
                        return;
                    call_handshake(temp, connection_id);
                });
            } catch (const std::exception& e) {
                log_callback_error("handshake_worker", e.what());
            }
        } else if (authed && fresh_eid && has_on_exchange_) {
            const std::string id = conn->cid;
            try {
                exchanges_.submit([this, id, eid, connection_id] {
                    auto current = find(id);
                    if (!current || current->closed || current->connection_id != connection_id)
                        return;
                    call_exchange(id, eid, connection_id);
                });
            } catch (const std::exception& e) {
                log_callback_error("on_exchange", e.what());
            }
        }
        return true;
    }
    void call_handshake(std::string temp, uint64_t connection_id) {
        auto conn = find_temp(temp);
        if (!conn || conn->closed || conn->connection_id != connection_id) return;
        py::gil_scoped_acquire acquire;
        try {
            handshake_worker_(as_bytes(temp));
        } catch (py::error_already_set& e) {
            log_callback_error("handshake_worker", e.what());
        }
    }
    void call_exchange(std::string id, std::string eid, uint64_t connection_id) {
        auto conn = find(id);
        if (!conn || conn->closed || conn->connection_id != connection_id) return;
        {
            std::lock_guard<std::mutex> lock(conn->mutex);
            if (!conn->eid_activity.count(eid)) return;
        }
        py::gil_scoped_acquire acquire;
        try {
            on_exchange_(as_bytes(id), as_bytes(eid));
        } catch (py::error_already_set& e) {
            log_callback_error("on_exchange", e.what());
        }
    }
    void read_ready(const std::shared_ptr<Conn>& conn) {
        uint8_t buffer[16 * 1024];
        size_t total_read = 0;
        while (!conn->closed && total_read < MAX_READ_PER_TICK) {
            if (conn->backpressure || !has_recv_room(conn)) return;
            const size_t request = std::min(sizeof(buffer), MAX_READ_PER_TICK - total_read);
#ifdef _WIN32
            const int got = ::recv(conn->sock, reinterpret_cast<char*>(buffer),
                                   static_cast<int>(request), 0);
#else
            const ssize_t got = ::recv(conn->sock, buffer, request, 0);
#endif
            if (got > 0) {
                total_read += static_cast<size_t>(got);
                try {
                    if (static_cast<size_t>(got) > MAX_INPUT_BUFFER - conn->input.size() ||
                        !ensure_input_capacity(*conn, conn->input.size() + static_cast<size_t>(got))) {
                        conn->closed = true;
                        return;
                    }
                    conn->input.insert(conn->input.end(), buffer, buffer + got);
                    const uint64_t id = conn->connection_id;
                    parse_buffered(conn, [&](bool authed, const std::string& eid,
                                             std::string payload, std::shared_ptr<Lease> memory) {
                        return deliver_message(conn, authed, eid, std::move(payload),
                                               std::move(memory), id);
                    });
                } catch (...) {
                    conn->closed = true;
                    conn->cv.notify_all();
                    return;
                }
                if (conn->closed || !has_recv_room(conn)) return;
                continue;
            }
            if (got == 0) {
                conn->closed = true;
                conn->cv.notify_all();
                return;
            }
            if (would_block(sockerr())) return;
            conn->closed = true;
            conn->cv.notify_all();
            return;
        }
    }
    bool has_pending_write(const std::shared_ptr<Conn>& conn) {
        if (conn->wire_off < conn->wire.size()) return true;
        std::lock_guard<std::mutex> lock(conn->mutex);
        return !conn->sendq.empty();
    }
    void write_ready(const std::shared_ptr<Conn>& conn) {
        if (conn->closed) return;
        if (conn->wire_off >= conn->wire.size()) {
            std::vector<uint8_t>().swap(conn->wire);
            conn->wire_off = 0;
            conn->wire_memory.reset();
            Pending pending;
            bool have_pending = false;
            {
                std::lock_guard<std::mutex> lock(conn->mutex);
                if (!conn->sendq.empty()) {
                    pending = std::move(conn->sendq.front());
                    conn->sendq.pop_front();
                    have_pending = true;
                }
            }
            if (!have_pending) return;
            const size_t header_size = pending.authed ? AUTH_HEAD + EID_N : UNAUTH_HEAD;
            const size_t frame_size = MAGIC_N + header_size + pending.payload.size() + MAGIC_N;
            try {
                conn->wire_memory = Lease::make(conn->global_memory, conn->local_memory, frame_size);
            } catch (...) {
                conn->closed = true;
                conn->cv.notify_all();
                return;
            }
            if (!conn->wire_memory) {
                conn->closed = true;
                conn->cv.notify_all();
                return;
            }
            try {
                conn->wire = make_frame(*conn, pending);
            } catch (...) {
                conn->closed = true;
                conn->cv.notify_all();
                return;
            }
        }
        if (conn->wire_off >= conn->wire.size()) return;
        const size_t amount = std::min(MAX_WRITE_PER_TICK, conn->wire.size() - conn->wire_off);
#ifdef _WIN32
        const int sent = ::send(conn->sock,
                                reinterpret_cast<const char*>(conn->wire.data() + conn->wire_off),
                                static_cast<int>(amount), 0);
#else
#  ifdef MSG_NOSIGNAL
        const ssize_t sent = ::send(conn->sock, conn->wire.data() + conn->wire_off,
                                    amount, MSG_NOSIGNAL);
#  else
        const ssize_t sent = ::send(conn->sock, conn->wire.data() + conn->wire_off,
                                    amount, 0);
#  endif
#endif
        if (sent > 0) {
            conn->wire_off += static_cast<size_t>(sent);
            if (conn->wire_off == conn->wire.size()) {
                std::vector<uint8_t>().swap(conn->wire);
                conn->wire_off = 0;
                conn->wire_memory.reset();
            }
            return;
        }
        if (sent < 0 && would_block(sockerr())) return;
        conn->closed = true;
        conn->cv.notify_all();
    }
    void cleanup_closed() {
        std::vector<std::shared_ptr<Conn>> dead;
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            auto it = connections_.begin();
            while (it != connections_.end()) {
                if ((*it)->closed) {
                    dead.push_back(*it);
                    it = connections_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (const auto& conn : dead) {
            {
                std::lock_guard<std::mutex> lock(ids_mutex_);
                for (auto it = ids_.begin(); it != ids_.end();) {
                    if (it->second == conn) it = ids_.erase(it);
                    else ++it;
                }
                for (auto it = temporary_ids_.begin(); it != temporary_ids_.end();) {
                    if (it->second == conn) it = temporary_ids_.erase(it);
                    else ++it;
                }
            }
            auto peer = peer_counts_.find(conn->peer);
            if (peer != peer_counts_.end()) {
                if (peer->second > 1) --peer->second;
                else peer_counts_.erase(peer);
            }
            clear_conn_io_state(conn);
        }
    }
    std::vector<std::shared_ptr<Conn>> connection_snapshot() {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        return connections_;
    }
    void io_loop() noexcept {
        while (running_.load()) {
            try {
                auto connections = connection_snapshot();
                const auto now = std::chrono::steady_clock::now();
                for (const auto& conn : connections) {
                    if (conn->closed) continue;
                    if (!conn->authed && now - conn->connect_time > UNAUTH_TIMEOUT) {
                        conn->closed = true;
                        conn->cv.notify_all();
                        continue;
                    }
                    try {
                        cleanup_exchanges(conn);
                        if (!conn->input.empty() && has_recv_room(conn)) {
                            const uint64_t id = conn->connection_id;
                            parse_buffered(conn, [&](bool authed, const std::string& eid,
                                                     std::string payload, std::shared_ptr<Lease> memory) {
                                return deliver_message(conn, authed, eid, std::move(payload),
                                                       std::move(memory), id);
                            });
                        }
                    } catch (...) {
                        conn->closed = true;
                        conn->cv.notify_all();
                    }
                }
                cleanup_closed();
                if (!running_.load()) break;
                std::vector<pollfd_t> poll_fds;
                std::vector<std::shared_ptr<Conn>> poll_connections;
                const socket_t listener = listener_;
                size_t listener_index = static_cast<size_t>(-1);
                if (listener != BAD_SOCKET) {
                    pollfd_t pfd{};
                    pfd.fd = listener;
                    pfd.events = POLLIN;
                    listener_index = poll_fds.size();
                    poll_fds.push_back(pfd);
                    poll_connections.push_back(nullptr);
                }
                connections = connection_snapshot();
                for (const auto& conn : connections) {
                    if (conn->closed || conn->sock == BAD_SOCKET) continue;
                    short events = 0;
                    if (!conn->backpressure && has_recv_room(conn)) events |= POLLIN;
                    if (has_pending_write(conn)) events |= POLLOUT;
                    pollfd_t pfd{};
                    pfd.fd = conn->sock;
                    pfd.events = events;
                    poll_fds.push_back(pfd);
                    poll_connections.push_back(conn);
                }
                const int rc = poll_many(poll_fds.data(), poll_fds.size(), IO_POLL_INTERVAL_MS);
                if (rc < 0) {
                    if (interrupted_error(sockerr())) continue;
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                if (!running_.load()) break;
                if (rc == 0) continue;
                if (listener_index != static_cast<size_t>(-1) &&
                    (poll_fds[listener_index].revents & POLLIN)) {
                    accept_ready();
                }
                for (size_t i = 0; i < poll_fds.size(); ++i) {
                    if (i == listener_index) continue;
                    const auto& conn = poll_connections[i];
                    if (!conn || conn->closed) continue;
                    const short revents = poll_fds[i].revents;
                    if (revents & (POLLERR | POLLNVAL)) {
                        conn->closed = true;
                        conn->cv.notify_all();
                        continue;
                    }
                    if ((revents & POLLHUP) && !(poll_fds[i].events & POLLIN) &&
                        !(poll_fds[i].events & POLLOUT)) {
                        continue;
                    }
                    if (revents & POLLOUT) write_ready(conn);
                    if (!conn->closed && (revents & POLLIN)) read_ready(conn);
                    if (!conn->closed && (revents & POLLHUP) &&
                        (poll_fds[i].events & POLLIN) && !(revents & POLLIN)) {
                        conn->closed = true;
                        conn->cv.notify_all();
                    }
                }
                cleanup_closed();
            } catch (const std::exception& e) {
                log_callback_error("server_io", e.what());
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            } catch (...) {
                log_callback_error("server_io", "unknown exception");
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        cleanup_closed();
    }
    std::string host_;
    uint16_t port_;
    std::string magic1_;
    std::string magic2_;
    py::object handshake_worker_;
    py::object on_exchange_;
    bool has_handshake_worker_;
    bool has_on_exchange_;
    std::shared_ptr<Quota> global_memory_;
    Pool handshakes_;
    Pool exchanges_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    socket_t listener_ = BAD_SOCKET;
    std::thread io_thread_;
    std::mutex ids_mutex_;
    std::mutex connections_mutex_;
    std::map<std::string, std::shared_ptr<Conn>> ids_;
    std::map<std::string, std::shared_ptr<Conn>> temporary_ids_;
    std::vector<std::shared_ptr<Conn>> connections_;
    std::map<std::string, size_t> peer_counts_;
    std::map<std::string, std::deque<std::chrono::steady_clock::time_point>> peer_accepts_;
    std::chrono::steady_clock::time_point last_peer_cleanup_ = std::chrono::steady_clock::now();
    uint64_t next_connection_id_ = 1;
};
class Client {
public:
    Client(std::string host, uint16_t port, py::object on_exchange,
           size_t simultaneous_exchanges)
        : host_(std::move(host)),
          port_(port),
          on_exchange_(std::move(on_exchange)),
          has_on_exchange_(!on_exchange_.is_none()),
          global_memory_(std::make_shared<Quota>(MAX_CONNECTION_BUFFERED_BYTES)),
          exchanges_(simultaneous_exchanges) {
        init_sockets();
        connect();
    }
    ~Client() {
        if (PyGILState_Check()) {
            py::gil_scoped_release release;
            close();
        } else {
            close();
        }
    }
    void connect() {
        if (connected_.load()) throw std::runtime_error("already connected");
        if (stopping_.load()) throw std::runtime_error("client has been closed");
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* results = nullptr;
        const std::string service = std::to_string(port_);
        if (getaddrinfo(host_.c_str(), service.c_str(), &hints, &results) != 0)
            throw std::runtime_error("getaddrinfo failed");
        socket_t sock = BAD_SOCKET;
        const auto connect_deadline = std::chrono::steady_clock::now() + CONNECT_TIMEOUT;
        for (addrinfo* item = results; item; item = item->ai_next) {
            if (std::chrono::steady_clock::now() >= connect_deadline) break;
            sock = ::socket(item->ai_family, item->ai_socktype, item->ai_protocol);
            if (sock == BAD_SOCKET) continue;
            if (connect_with_deadline(sock, item->ai_addr,
                                      static_cast<socket_len_t>(item->ai_addrlen),
                                      connect_deadline)) {
                break;
            }
            close_sock(sock);
            sock = BAD_SOCKET;
        }
        freeaddrinfo(results);
        if (sock == BAD_SOCKET) throw std::runtime_error("connect failed or timed out");
        std::array<char, MAGIC_N * 2> greeting{};
        size_t received = 0;
        const auto greeting_deadline = std::chrono::steady_clock::now() + GREETING_TIMEOUT;
        while (received < greeting.size()) {
            if (!wait_socket(sock, POLLIN, greeting_deadline)) {
                close_sock(sock);
                throw std::runtime_error("timed out receiving framing greeting");
            }
#ifdef _WIN32
            const int got = ::recv(sock, greeting.data() + received,
                                   static_cast<int>(greeting.size() - received), 0);
#else
            const ssize_t got = ::recv(sock, greeting.data() + received,
                                       greeting.size() - received, 0);
#endif
            if (got > 0) {
                received += static_cast<size_t>(got);
            } else if (got < 0 && would_block(sockerr())) {
                continue;
            } else {
                close_sock(sock);
                throw std::runtime_error("failed to receive framing greeting");
            }
        }
        tune_socket(sock);
        auto conn = std::make_shared<Conn>(global_memory_);
        conn->sock = sock;
        conn->connection_id = 1;
        conn->magic1.assign(greeting.data(), MAGIC_N);
        conn->magic2.assign(greeting.data() + MAGIC_N, MAGIC_N);
        magic1_ = conn->magic1;
        magic2_ = conn->magic2;
        conn_ = conn;
        connected_ = true;
        try {
            io_thread_ = std::thread([this] { io_loop(); });
        } catch (...) {
            connected_ = false;
            clear_conn_io_state(conn_);
            conn_.reset();
            throw;
        }
    }
    void close() {
        if (stopping_.exchange(true)) return;
        connected_ = false;
        auto conn = conn_;
        if (conn) {
            conn->closed = true;
            conn->cv.notify_all();
        }
        if (io_thread_.joinable() && io_thread_.get_id() != std::this_thread::get_id())
            io_thread_.join();
        if (conn) clear_conn_io_state(conn);
        exchanges_.stop();
    }
    py::object send(py::bytes payload_bytes, py::object eid_obj) {
        auto conn = conn_;
        if (!conn || !connected_.load()) throw std::runtime_error("not connected");
        if (!conn->authed.load(std::memory_order_acquire))
            throw std::runtime_error(
                "normal send is unavailable before authentication; use send_handshake(data)");
        const std::string payload = as_string(payload_bytes);
        auto requested_eid = eid_arg(eid_obj);
        std::string eid;
        if (requested_eid) {
            eid = *requested_eid;
            const EidResult result = touch_eid(conn, eid);
            if (result == EidResult::Limit)
                throw py::value_error("too many active eids for this connection");
            if (result == EidResult::Closed)
                throw std::runtime_error("connection closed");
        } else {
            bool generated = false;
            for (int tries = 0; tries < 16; ++tries) {
                eid = random_bytes(EID_N);
                const EidResult result = touch_eid(conn, eid);
                if (result == EidResult::Fresh) {
                    generated = true;
                    break;
                }
                if (result == EidResult::Limit)
                    throw py::value_error("too many active eids for this connection");
                if (result == EidResult::Closed)
                    throw std::runtime_error("connection closed");
            }
            if (!generated) throw std::runtime_error("could not generate a unique eid");
        }
        enqueue(Pending{payload, eid, true, {}});
        return py::object(as_bytes(eid));
    }
    void send_handshake(py::bytes payload_bytes) {
        auto conn = conn_;
        if (!conn || !connected_.load() || conn->authed.load(std::memory_order_acquire))
            throw std::runtime_error("handshake send only allowed while connected and unauthenticated");
        enqueue(Pending{as_string(payload_bytes), {}, false, {}});
    }
    py::object recv(py::object eid_obj, py::object timeout_obj) {
        auto conn = conn_;
        if (!conn || !conn->authed.load(std::memory_order_acquire))
            throw std::runtime_error(
                "normal recv is unavailable before authentication; use recv_handshake()");
        auto eid = eid_arg(eid_obj);
        if (!eid) throw py::value_error("eid is required for authenticated recv");
        return pop(eid, true, timeout_arg(timeout_obj));
    }
    py::object recv_handshake(py::object timeout_obj) {
        auto conn = conn_;
        if (!conn || conn->authed.load(std::memory_order_acquire))
            throw std::runtime_error("handshake recv only allowed before authentication");
        return pop({}, false, timeout_arg(timeout_obj));
    }
    bool auth_finished() {
        if (!conn_ || !connected_.load()) throw std::runtime_error("not connected");
        conn_->authed.store(true, std::memory_order_release);
        conn_->cv.notify_all();
        return true;
    }
    bool is_authed() const {
        return conn_ && conn_->authed.load(std::memory_order_acquire);
    }
    py::bytes cid() const {
        return conn_ && conn_->authed.load(std::memory_order_acquire)
            ? as_bytes(conn_->cid) : py::bytes();
    }
    py::bytes MAGIC1() const { return as_bytes(magic1_); }
    py::bytes MAGIC2() const { return as_bytes(magic2_); }
    void set_backpressure(bool value) {
        if (!conn_) throw std::runtime_error("not connected");
        conn_->backpressure = value;
    }
private:
    void enqueue(Pending pending) {
        auto conn = conn_;
        if (!conn) throw std::runtime_error("not connected");
        const size_t max_payload = pending.authed ? MAX_AUTH : MAX_UNAUTH;
        if (pending.payload.size() > max_payload) {
            if (pending.authed) throw py::value_error("payload exceeds 25-bit length limit");
            throw py::value_error("handshake payload exceeds 65535 bytes");
        }
        std::lock_guard<std::mutex> lock(conn->mutex);
        if (conn->closed) throw std::runtime_error("connection closed");
        if (conn->sendq.size() >= QUEUE_LIMIT)
            throw py::value_error("send queue full (maximum 8)");
        pending.memory = Lease::make(conn->global_memory, conn->local_memory,
                                     pending.payload.size() + sizeof(Pending) + 32);
        if (!pending.memory) throw py::value_error("buffer budget exhausted");
        conn->sendq.push_back(std::move(pending));
    }
    py::object pop(const std::optional<std::string>& eid, bool want_authed,
                   const std::optional<double>& timeout) {
        auto conn = conn_;
        if (!conn) return py::none();
        std::unique_lock<std::mutex> lock(conn->mutex);
        auto predicate = [&] {
            if (conn->closed || conn->authed.load(std::memory_order_acquire) != want_authed)
                return true;
            return std::any_of(conn->recvq.begin(), conn->recvq.end(), [&](const Message& message) {
                return message.authed == want_authed && (!want_authed || message.eid == *eid);
            });
        };
        bool ready = false;
        {
            py::gil_scoped_release release;
            if (timeout) {
                ready = conn->cv.wait_for(lock, std::chrono::duration<double>(*timeout), predicate);
            } else {
                conn->cv.wait(lock, predicate);
                ready = true;
            }
        }
        if (!ready) {
            lock.unlock();
            return py::none();
        }
        auto it = std::find_if(conn->recvq.begin(), conn->recvq.end(), [&](const Message& message) {
            return message.authed == want_authed && (!want_authed || message.eid == *eid);
        });
        if (it == conn->recvq.end()) {
            lock.unlock();
            return py::none();
        }
        std::string payload = std::move(it->payload);
        conn->recvq.erase(it);
        lock.unlock();
        return py::object(as_bytes(payload));
    }
    void cleanup_exchanges(const std::shared_ptr<Conn>& conn) {
        const auto now = std::chrono::steady_clock::now();
        if (now - conn->last_cleanup < CLEANUP_INTERVAL) return;
        conn->last_cleanup = now;
        std::vector<std::string> expired;
        {
            std::lock_guard<std::mutex> lock(conn->mutex);
            for (auto it = conn->eid_activity.begin(); it != conn->eid_activity.end();) {
                if (now - it->second >= EID_TTL) {
                    expired.push_back(it->first);
                    it = conn->eid_activity.erase(it);
                } else {
                    ++it;
                }
            }
            if (!expired.empty()) {
                auto is_expired = [&](const std::string& id) {
                    return std::binary_search(expired.begin(), expired.end(), id);
                };
                conn->recvq.erase(std::remove_if(conn->recvq.begin(), conn->recvq.end(),
                    [&](const Message& message) { return message.authed && is_expired(message.eid); }),
                    conn->recvq.end());
                conn->sendq.erase(std::remove_if(conn->sendq.begin(), conn->sendq.end(),
                    [&](const Pending& pending) { return pending.authed && is_expired(pending.eid); }),
                    conn->sendq.end());
                conn->cv.notify_all();
            }
        }
    }
    bool deliver_message(const std::shared_ptr<Conn>& conn, bool authed,
                         const std::string& eid, std::string payload,
                         std::shared_ptr<Lease> memory, uint64_t connection_id) {
        bool fresh_eid = false;
        try {
            std::lock_guard<std::mutex> lock(conn->mutex);
            if (conn->closed || conn->recvq.size() >= QUEUE_LIMIT) return false;
            if (authed) {
                const auto now = std::chrono::steady_clock::now();
                auto it = conn->eid_activity.find(eid);
                if (it != conn->eid_activity.end()) {
                    it->second = now;
                } else {
                    for (auto old = conn->eid_activity.begin(); old != conn->eid_activity.end();) {
                        if (now - old->second >= EID_TTL) old = conn->eid_activity.erase(old);
                        else ++old;
                    }
                    if (conn->eid_activity.size() >= MAX_ACTIVE_EIDS_PER_CONNECTION) {
                        conn->closed = true;
                        conn->cv.notify_all();
                        return false;
                    }
                    conn->eid_activity.emplace(eid, now);
                    fresh_eid = true;
                }
            }
            conn->recvq.push_back(Message{eid, std::move(payload), authed, std::move(memory)});
            conn->cv.notify_all();
        } catch (...) {
            conn->closed = true;
            conn->cv.notify_all();
            return false;
        }
        if (authed && fresh_eid && has_on_exchange_) {
            try {
                exchanges_.submit([this, eid, connection_id] {
                    auto current = conn_;
                    if (!current || current->closed || current->connection_id != connection_id)
                        return;
                    call_exchange(eid, connection_id);
                });
            } catch (const std::exception& e) {
                log_callback_error("on_exchange", e.what());
            }
        }
        return true;
    }
    void call_exchange(std::string eid, uint64_t connection_id) {
        auto conn = conn_;
        if (!conn || conn->closed || conn->connection_id != connection_id) return;
        {
            std::lock_guard<std::mutex> lock(conn->mutex);
            if (!conn->eid_activity.count(eid)) return;
        }
        py::gil_scoped_acquire acquire;
        try {
            on_exchange_(as_bytes(eid));
        } catch (py::error_already_set& e) {
            log_callback_error("on_exchange", e.what());
        }
    }
    bool has_pending_write(const std::shared_ptr<Conn>& conn) {
        if (conn->wire_off < conn->wire.size()) return true;
        std::lock_guard<std::mutex> lock(conn->mutex);
        return !conn->sendq.empty();
    }
    void write_ready(const std::shared_ptr<Conn>& conn) {
        if (conn->closed) return;
        if (conn->wire_off >= conn->wire.size()) {
            std::vector<uint8_t>().swap(conn->wire);
            conn->wire_off = 0;
            conn->wire_memory.reset();
            Pending pending;
            bool have_pending = false;
            {
                std::lock_guard<std::mutex> lock(conn->mutex);
                if (!conn->sendq.empty()) {
                    pending = std::move(conn->sendq.front());
                    conn->sendq.pop_front();
                    have_pending = true;
                }
            }
            if (!have_pending) return;
            const size_t header_size = pending.authed ? AUTH_HEAD + EID_N : UNAUTH_HEAD;
            const size_t frame_size = MAGIC_N + header_size + pending.payload.size() + MAGIC_N;
            try {
                conn->wire_memory = Lease::make(conn->global_memory, conn->local_memory, frame_size);
            } catch (...) {
                conn->closed = true;
                conn->cv.notify_all();
                return;
            }
            if (!conn->wire_memory) {
                conn->closed = true;
                conn->cv.notify_all();
                return;
            }
            try {
                conn->wire = make_frame(*conn, pending);
            } catch (...) {
                conn->closed = true;
                conn->cv.notify_all();
                return;
            }
        }
        if (conn->wire_off >= conn->wire.size()) return;
        const size_t amount = std::min(MAX_WRITE_PER_TICK, conn->wire.size() - conn->wire_off);
#ifdef _WIN32
        const int sent = ::send(conn->sock,
                                reinterpret_cast<const char*>(conn->wire.data() + conn->wire_off),
                                static_cast<int>(amount), 0);
#else
#  ifdef MSG_NOSIGNAL
        const ssize_t sent = ::send(conn->sock, conn->wire.data() + conn->wire_off,
                                    amount, MSG_NOSIGNAL);
#  else
        const ssize_t sent = ::send(conn->sock, conn->wire.data() + conn->wire_off,
                                    amount, 0);
#  endif
#endif
        if (sent > 0) {
            conn->wire_off += static_cast<size_t>(sent);
            if (conn->wire_off == conn->wire.size()) {
                std::vector<uint8_t>().swap(conn->wire);
                conn->wire_off = 0;
                conn->wire_memory.reset();
            }
            return;
        }
        if (sent < 0 && would_block(sockerr())) return;
        conn->closed = true;
        conn->cv.notify_all();
    }
    void read_ready(const std::shared_ptr<Conn>& conn) {
        uint8_t buffer[16 * 1024];
        size_t total_read = 0;
        while (!conn->closed && total_read < MAX_READ_PER_TICK) {
            if (conn->backpressure || !has_recv_room(conn)) return;
            const size_t request = std::min(sizeof(buffer), MAX_READ_PER_TICK - total_read);
#ifdef _WIN32
            const int got = ::recv(conn->sock, reinterpret_cast<char*>(buffer),
                                   static_cast<int>(request), 0);
#else
            const ssize_t got = ::recv(conn->sock, buffer, request, 0);
#endif
            if (got > 0) {
                total_read += static_cast<size_t>(got);
                try {
                    if (static_cast<size_t>(got) > MAX_INPUT_BUFFER - conn->input.size() ||
                        !ensure_input_capacity(*conn, conn->input.size() + static_cast<size_t>(got))) {
                        conn->closed = true;
                        return;
                    }
                    conn->input.insert(conn->input.end(), buffer, buffer + got);
                    const uint64_t id = conn->connection_id;
                    parse_buffered(conn, [&](bool authed, const std::string& eid,
                                             std::string payload, std::shared_ptr<Lease> memory) {
                        return deliver_message(conn, authed, eid, std::move(payload),
                                               std::move(memory), id);
                    });
                } catch (...) {
                    conn->closed = true;
                    conn->cv.notify_all();
                    return;
                }
                if (conn->closed || !has_recv_room(conn)) return;
                continue;
            }
            if (got == 0) {
                conn->closed = true;
                conn->cv.notify_all();
                return;
            }
            if (would_block(sockerr())) return;
            conn->closed = true;
            conn->cv.notify_all();
            return;
        }
    }
    void io_loop() noexcept {
        auto conn = conn_;
        if (!conn) return;
        while (connected_.load() && !conn->closed) {
            try {
                try {
                    cleanup_exchanges(conn);
                    if (!conn->input.empty() && has_recv_room(conn)) {
                        const uint64_t id = conn->connection_id;
                        parse_buffered(conn, [&](bool authed, const std::string& eid,
                                                 std::string payload, std::shared_ptr<Lease> memory) {
                            return deliver_message(conn, authed, eid, std::move(payload),
                                                   std::move(memory), id);
                        });
                    }
                } catch (...) {
                    conn->closed = true;
                    conn->cv.notify_all();
                }
                if (conn->closed || !connected_.load()) break;
                short events = 0;
                if (!conn->backpressure && has_recv_room(conn)) events |= POLLIN;
                if (has_pending_write(conn)) events |= POLLOUT;
                pollfd_t pfd{};
                pfd.fd = conn->sock;
                pfd.events = events;
                const int rc = poll_many(&pfd, 1, IO_POLL_INTERVAL_MS);
                if (rc < 0) {
                    if (interrupted_error(sockerr())) continue;
                    conn->closed = true;
                    break;
                }
                if (rc == 0) continue;
                if (pfd.revents & (POLLERR | POLLNVAL)) {
                    conn->closed = true;
                    break;
                }
                if ((pfd.revents & POLLHUP) && !(pfd.events & POLLIN) &&
                    !(pfd.events & POLLOUT))
                    continue;
                if (pfd.revents & POLLOUT) write_ready(conn);
                if (!conn->closed && (pfd.revents & POLLIN)) read_ready(conn);
                if (!conn->closed && (pfd.revents & POLLHUP) &&
                    (pfd.events & POLLIN) && !(pfd.revents & POLLIN)) {
                    conn->closed = true;
                    break;
                }
            } catch (const std::exception& e) {
                log_callback_error("client_io", e.what());
                conn->closed = true;
            } catch (...) {
                log_callback_error("client_io", "unknown exception");
                conn->closed = true;
            }
        }
        connected_ = false;
        clear_conn_io_state(conn);
    }
    std::string host_;
    uint16_t port_;
    py::object on_exchange_;
    bool has_on_exchange_;
    std::shared_ptr<Quota> global_memory_;
    Pool exchanges_;
    std::shared_ptr<Conn> conn_;
    std::string magic1_;
    std::string magic2_;
    std::atomic<bool> connected_{false};
    std::atomic<bool> stopping_{false};
    std::thread io_thread_;
};
}
PYBIND11_MODULE(backend, m) {
    m.doc() = "Networking v2.0 queued TCP backend (resource-hardened)";
    m.attr("MAX_UNAUTH_PAYLOAD") = MAX_UNAUTH;
    m.attr("MAX_AUTH_PAYLOAD") = MAX_AUTH;
    m.attr("QUEUE_LIMIT") = QUEUE_LIMIT;
    py::class_<Server>(m, "Server")
        .def(py::init<std::string, uint16_t, py::object, py::object, size_t, size_t>(),
             py::arg("host"), py::arg("port"),
             py::arg("handshake_worker") = py::none(),
             py::arg("on_exchange") = py::none(),
             py::arg("simult_handshakes") = 4,
             py::arg("simult_exchanges") = 4)
        .def("start", &Server::start)
        .def("stop", [](Server& s) { py::gil_scoped_release release; s.stop(); })
        .def("send", [](Server& s, py::bytes data, py::bytes cid, py::object eid) {
            return s.send(data, cid, eid);
        }, py::arg("data"), py::arg("cid"), py::arg("eid") = py::none())
        .def("send_handshake", &Server::send_handshake,
             py::arg("temp_cid"), py::arg("data"))
        .def("recv", [](Server& s, py::bytes cid, py::object eid, py::object timeout) {
            return s.recv(cid, eid, timeout);
        }, py::arg("cid"), py::arg("eid"), py::arg("timeout") = py::none())
        .def("recv_handshake", [](Server& s, py::bytes cid, py::object timeout) {
            return s.recv_handshake(cid, timeout);
        }, py::arg("temp_cid"), py::arg("timeout") = py::none())
        .def("auth_finished", &Server::auth_finished,
             py::arg("temp_cid"), py::arg("new_cid"),
             py::arg("confirmation_payload") = py::none())
        .def("is_authed", &Server::is_authed)
        .def("set_backpressure", &Server::set_backpressure)
        .def("close_client", &Server::close_client)
        .def_property_readonly("MAGIC1", &Server::MAGIC1)
        .def_property_readonly("MAGIC2", &Server::MAGIC2);
    py::class_<Client>(m, "Client")
        .def(py::init<std::string, uint16_t, py::object, size_t>(),
             py::arg("host"), py::arg("port"),
             py::arg("on_exchange") = py::none(),
             py::arg("simult_exchanges") = 4)
        .def("close", [](Client& c) { py::gil_scoped_release release; c.close(); })
        .def("send", [](Client& c, py::bytes data, py::object eid) {
            return c.send(data, eid);
        }, py::arg("data"), py::arg("eid") = py::none())
        .def("send_handshake", &Client::send_handshake)
        .def("recv", [](Client& c, py::object eid, py::object timeout) {
            return c.recv(eid, timeout);
        }, py::arg("eid"), py::arg("timeout") = py::none())
        .def("recv_handshake", [](Client& c, py::object timeout) {
            return c.recv_handshake(timeout);
        }, py::arg("timeout") = py::none())
        .def("auth_finished", &Client::auth_finished)
        .def_property_readonly("is_authed", &Client::is_authed)
        .def_property_readonly("cid", &Client::cid)
        .def_property_readonly("MAGIC1", &Client::MAGIC1)
        .def_property_readonly("MAGIC2", &Client::MAGIC2)
        .def("set_backpressure", &Client::set_backpressure);
}
