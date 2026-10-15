#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")
using socket_t = SOCKET;
static constexpr socket_t INVALID_SOCKET_VALUE = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t INVALID_SOCKET_VALUE = -1;
#endif

namespace py = pybind11;
namespace {

// Framing constants. The authenticated header is 4-byte length + 1-byte flag.
constexpr std::size_t MAGIC_SIZE = 8;
constexpr std::size_t EID_SIZE = 8;
constexpr std::size_t UNAUTH_HEADER_SIZE = 2;
constexpr std::size_t AUTH_HEADER_SIZE = 5;
constexpr std::size_t MAX_UNAUTH_PAYLOAD = 65535;
constexpr std::size_t MAX_AUTH_PAYLOAD = 33554431;
constexpr std::size_t RECV_CHUNK_SIZE = 65536;
constexpr char AUTH_FLAG_ZERO = '0';
constexpr char AUTH_FLAG_ONE = '1';
constexpr char AUTH_FLAG_SENT = '0';

#ifdef _WIN32
struct SocketRuntime {
    SocketRuntime() {
        WSADATA data{};
        const int rc = WSAStartup(MAKEWORD(2, 2), &data);
        if (rc != 0) throw std::runtime_error("WSAStartup failed: " + std::to_string(rc));
    }
};
#else
struct SocketRuntime { SocketRuntime() = default; };
#endif

void ensure_socket_runtime() {
    static SocketRuntime runtime;
    (void)runtime;
}

void close_socket(socket_t s) {
    if (s == INVALID_SOCKET_VALUE) return;
#ifdef _WIN32
    ::shutdown(s, SD_BOTH);
    ::closesocket(s);
#else
    ::shutdown(s, SHUT_RDWR);
    ::close(s);
#endif
}

int last_socket_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

bool socket_error_retryable(int error) {
#ifdef _WIN32
    return error == WSAEINTR || error == WSAEWOULDBLOCK;
#else
    return error == EINTR || error == EAGAIN || error == EWOULDBLOCK;
#endif
}

bool socket_send_all(socket_t s, const std::uint8_t* data, std::size_t len) {
    std::size_t sent = 0;
    while (sent < len) {
#ifdef _WIN32
        const int amount = static_cast<int>(std::min<std::size_t>(len - sent, static_cast<std::size_t>(std::numeric_limits<int>::max())));
        const int n = ::send(s, reinterpret_cast<const char*>(data + sent), amount, 0);
#else
        const std::size_t amount = std::min<std::size_t>(len - sent, static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()));
        const ssize_t n = ::send(s, data + sent, amount, MSG_NOSIGNAL);
#endif
        if (n < 0) {
            if (socket_error_retryable(last_socket_error())) continue;
            return false;
        }
        if (n == 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

bool socket_recv_exact(socket_t s, std::uint8_t* out, std::size_t len) {
    std::size_t received = 0;
    while (received < len) {
#ifdef _WIN32
        const int amount = static_cast<int>(len - received);
        const int n = ::recv(s, reinterpret_cast<char*>(out + received), amount, 0);
#else
        const ssize_t n = ::recv(s, out + received, len - received, 0);
#endif
        if (n < 0) {
            if (socket_error_retryable(last_socket_error())) continue;
            return false;
        }
        if (n == 0) return false;
        received += static_cast<std::size_t>(n);
    }
    return true;
}

void secure_random(std::uint8_t* out, std::size_t len) {
#ifdef _WIN32
    if (BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw std::runtime_error("BCryptGenRandom failed");
#else
    FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f) throw std::runtime_error("Could not open /dev/urandom");
    const std::size_t n = std::fread(out, 1, len, f);
    std::fclose(f);
    if (n != len) throw std::runtime_error("Could not read enough bytes from /dev/urandom");
#endif
}

std::string random_bytes(std::size_t len) {
    std::string result(len, '\0');
    secure_random(reinterpret_cast<std::uint8_t*>(result.data()), len);
    return result;
}

std::string pybytes_to_string(const py::bytes& value) {
    std::string result = value;  // pybind11 preserves embedded NUL bytes
    return result;
}

py::bytes string_to_pybytes(const std::string& value) {
    return py::bytes(value.data(), value.size());
}

std::uint16_t read_u16_be(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}
std::uint32_t read_u32_be(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}
void append_u16_be(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
}
void append_u32_be(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::size_t find_sequence(const std::vector<std::uint8_t>& haystack,
                          const std::string& needle,
                          std::size_t start,
                          std::size_t limit_exclusive = std::string::npos) {
    if (needle.empty() || start >= haystack.size()) return std::string::npos;
    const std::size_t last = std::min(haystack.size(), limit_exclusive);
    if (last < needle.size() || start > last - needle.size()) return std::string::npos;
    for (std::size_t i = start; i + needle.size() <= last; ++i) {
        if (std::memcmp(haystack.data() + i, needle.data(), needle.size()) == 0) return i;
    }
    return std::string::npos;
}

// Preserve a suffix that may be the beginning of MAGIC1 when a full marker is not present.
void trim_to_possible_magic_prefix(std::vector<std::uint8_t>& buffer, const std::string& magic1) {
    const std::size_t max_keep = std::min(buffer.size(), magic1.size() - 1);
    for (std::size_t keep = max_keep; keep > 0; --keep) {
        if (std::memcmp(buffer.data() + buffer.size() - keep, magic1.data(), keep) == 0) {
            buffer.erase(buffer.begin(), buffer.end() - static_cast<std::ptrdiff_t>(keep));
            return;
        }
    }
    buffer.clear();
}

class FifoExecutor {
public:
    explicit FifoExecutor(std::size_t concurrency) : concurrency_(concurrency) {
        if (concurrency_ == 0) throw std::invalid_argument("callback concurrency must be at least 1");
    }

    FifoExecutor(const FifoExecutor&) = delete;
    FifoExecutor& operator=(const FifoExecutor&) = delete;

    ~FifoExecutor() { stop(); }

    bool submit(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) return false;
            queue_.push_back(std::move(task));
            if (!started_) {
                started_ = true;
                workers_.reserve(concurrency_);
                for (std::size_t i = 0; i < concurrency_; ++i) {
                    workers_.emplace_back([this] { worker_loop(); });
                }
            }
        }
        cv_.notify_all();
        return true;
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_ && joined_) return;
            stopping_ = true;
            queue_.clear(); // callbacks not yet running are cancelled during shutdown
        }
        cv_.notify_all();
        for (auto& worker : workers_) {
            if (worker.joinable() && worker.get_id() != std::this_thread::get_id()) worker.join();
        }
        joined_ = true;
    }

private:
    void worker_loop() {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
                if (queue_.empty() && stopping_) return;
                task = std::move(queue_.front());
                queue_.pop_front();
            }
            try { task(); }
            catch (const std::exception& e) { std::cerr << "[network] background task failed: " << e.what() << '\n'; }
            catch (...) { std::cerr << "[network] background task failed with an unknown exception\n"; }
        }
    }

    const std::size_t concurrency_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::function<void()>> queue_;
    std::vector<std::thread> workers_;
    bool started_ = false;
    bool stopping_ = false;
    bool joined_ = false;
};

struct Connection {
    std::atomic<socket_t> sock{INVALID_SOCKET_VALUE};
    std::atomic<bool> is_authed{false};
    std::atomic<bool> backpressure{false};
    std::atomic<bool> closed{false};
    std::atomic<bool> handshake_triggered{false};
    std::atomic<bool> reader_done{false};
    bool is_server_side = false;

    std::string temp_cid;
    std::string public_cid; // empty until auth_finished
    std::string magic1;
    std::string magic2;

    std::mutex send_mutex;
    std::mutex identity_mutex;
    std::mutex message_mutex;
    std::condition_variable message_cv;
    std::deque<std::vector<std::uint8_t>> unauth_messages;
    std::map<std::string, std::deque<std::vector<std::uint8_t>>> exchange_messages;
    std::mutex exchanges_mutex;
    std::set<std::string> known_eids;

    void wake_receivers() { message_cv.notify_all(); }

    void push_message(const std::string& eid, std::vector<std::uint8_t> payload, bool authenticated) {
        {
            std::lock_guard<std::mutex> lock(message_mutex);
            if (authenticated) exchange_messages[eid].push_back(std::move(payload));
            else unauth_messages.push_back(std::move(payload));
        }
        message_cv.notify_all();
    }

    std::optional<std::vector<std::uint8_t>> pop_message(const std::optional<std::string>& eid,
                                                          const std::optional<double>& timeout) {
        std::unique_lock<std::mutex> lock(message_mutex);
        auto available = [&]() {
            if (closed.load()) return true;
            if (!eid.has_value()) return !unauth_messages.empty();
            auto it = exchange_messages.find(*eid);
            return it != exchange_messages.end() && !it->second.empty();
        };
        if (timeout.has_value()) {
            const auto duration = std::chrono::duration<double>(*timeout);
            if (!message_cv.wait_for(lock, duration, available)) return std::nullopt;
        } else {
            message_cv.wait(lock, available);
        }
        if (!eid.has_value()) {
            if (unauth_messages.empty()) return std::nullopt;
            auto value = std::move(unauth_messages.front());
            unauth_messages.pop_front();
            return value;
        }
        auto it = exchange_messages.find(*eid);
        if (it == exchange_messages.end() || it->second.empty()) return std::nullopt;
        auto value = std::move(it->second.front());
        it->second.pop_front();
        if (it->second.empty()) exchange_messages.erase(it);
        return value;
    }

    std::string current_id() {
        std::lock_guard<std::mutex> lock(identity_mutex);
        return is_authed.load() ? public_cid : temp_cid;
    }

    void mark_closed() {
        closed.store(true);
        message_cv.notify_all();
    }
};

std::optional<double> parse_timeout(const py::object& value) {
    if (value.is_none()) return std::nullopt;
    const double t = py::cast<double>(value);
    if (t < 0.0) throw py::value_error("timeout must be >= 0 or None");
    return t;
}

std::optional<std::string> parse_eid_object(const py::object& value) {
    if (value.is_none()) return std::nullopt;
    const std::string eid = py::cast<py::bytes>(value);
    if (eid.size() != EID_SIZE) throw py::value_error("eid must be exactly 8 bytes");
    return eid;
}

std::string require_nonempty_bytes(const py::bytes& value, const char* name) {
    std::string out = pybytes_to_string(value);
    if (out.empty()) throw py::value_error(std::string(name) + " must not be empty");
    return out;
}

std::vector<std::uint8_t> make_unauth_frame(const std::string& magic1,
                                             const std::string& magic2,
                                             const std::string& payload) {
    if (payload.size() > MAX_UNAUTH_PAYLOAD) throw std::invalid_argument("unauthenticated payload exceeds 65535 bytes");
    std::vector<std::uint8_t> frame;
    frame.reserve(MAGIC_SIZE + UNAUTH_HEADER_SIZE + payload.size() + MAGIC_SIZE);
    frame.insert(frame.end(), magic1.begin(), magic1.end());
    append_u16_be(frame, static_cast<std::uint16_t>(payload.size()));
    frame.insert(frame.end(), payload.begin(), payload.end());
    frame.insert(frame.end(), magic2.begin(), magic2.end());
    return frame;
}

std::vector<std::uint8_t> make_auth_frame(const std::string& magic1,
                                          const std::string& magic2,
                                          const std::string& eid,
                                          const std::string& payload) {
    if (eid.size() != EID_SIZE) throw std::invalid_argument("eid must be exactly 8 bytes");
    if (payload.size() > MAX_AUTH_PAYLOAD) throw std::invalid_argument("authenticated payload exceeds the configured 32 MiB limit");
    std::vector<std::uint8_t> frame;
    frame.reserve(MAGIC_SIZE + AUTH_HEADER_SIZE + EID_SIZE + payload.size() + MAGIC_SIZE);
    frame.insert(frame.end(), magic1.begin(), magic1.end());
    append_u32_be(frame, static_cast<std::uint32_t>(payload.size()));
    frame.push_back(static_cast<std::uint8_t>(AUTH_FLAG_SENT));
    frame.insert(frame.end(), eid.begin(), eid.end());
    frame.insert(frame.end(), payload.begin(), payload.end());
    frame.insert(frame.end(), magic2.begin(), magic2.end());
    return frame;
}

// Parser consumes as many complete frames as possible. It deliberately applies the requested
// resynchronization behavior when a marker appears unexpectedly inside a length-delimited frame.
// Returns false only when more data is needed; malformed bytes are discarded and parsing retries.
template <typename Deliver>
bool parse_frames(const std::shared_ptr<Connection>& conn,
                  std::vector<std::uint8_t>& buffer,
                  Deliver&& deliver) {
    bool made_progress = false;
    for (;;) {
        if (buffer.size() < MAGIC_SIZE) return made_progress;
        const std::size_t start = find_sequence(buffer, conn->magic1, 0);
        if (start == std::string::npos) {
            const std::size_t old_size = buffer.size();
            trim_to_possible_magic_prefix(buffer, conn->magic1);
            return made_progress || buffer.size() != old_size;
        }
        if (start > 0) {
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(start));
            made_progress = true;
        }

        const bool authenticated = conn->is_authed.load();
        const std::size_t header_size = authenticated ? AUTH_HEADER_SIZE + EID_SIZE : UNAUTH_HEADER_SIZE;
        const std::size_t payload_start = MAGIC_SIZE + header_size;
        if (buffer.size() < payload_start) return made_progress;

        std::uint32_t payload_len = 0;
        std::string eid;
        if (!authenticated) {
            payload_len = read_u16_be(buffer.data() + MAGIC_SIZE);
            if (payload_len > MAX_UNAUTH_PAYLOAD) {
                buffer.erase(buffer.begin());
                made_progress = true;
                continue;
            }
        } else {
            payload_len = read_u32_be(buffer.data() + MAGIC_SIZE);
            const std::uint8_t flag = buffer[MAGIC_SIZE + 4];
            if (flag != static_cast<std::uint8_t>(AUTH_FLAG_ZERO) && flag != static_cast<std::uint8_t>(AUTH_FLAG_ONE)) {
                buffer.erase(buffer.begin());
                made_progress = true;
                continue;
            }
            eid.assign(reinterpret_cast<const char*>(buffer.data() + MAGIC_SIZE + AUTH_HEADER_SIZE), EID_SIZE);
            if (payload_len > MAX_AUTH_PAYLOAD) {
                buffer.erase(buffer.begin());
                made_progress = true;
                continue;
            }
        }

        const std::size_t total = MAGIC_SIZE + header_size + static_cast<std::size_t>(payload_len) + MAGIC_SIZE;
        // Look for unexpected marker occurrences before the expected frame terminator. Whichever
        // marker occurs first determines resynchronization.
        const std::size_t magic1_inside = find_sequence(buffer, conn->magic1, MAGIC_SIZE);
        const std::size_t magic2_inside = find_sequence(buffer, conn->magic2, payload_start,
                                                        std::min(buffer.size(), total));
        const bool magic1_early = magic1_inside != std::string::npos && magic1_inside < total;
        const bool magic2_early = magic2_inside != std::string::npos && magic2_inside < total - MAGIC_SIZE;
        if (magic1_early || magic2_early) {
            if (magic1_early && (!magic2_early || magic1_inside < magic2_inside)) {
                buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(magic1_inside));
            } else {
                buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(magic2_inside + MAGIC_SIZE));
            }
            made_progress = true;
            continue;
        }

        if (buffer.size() < total) return made_progress;

        const std::size_t terminator_pos = total - MAGIC_SIZE;
        if (std::memcmp(buffer.data() + terminator_pos, conn->magic2.data(), MAGIC_SIZE) != 0) {
            // We have consumed the length-indicated number of bytes but did not see MAGIC2 where
            // required. Drop the presumed frame and continue trying to find the next frame.
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(total));
            made_progress = true;
            continue;
        }

        const char* payload_ptr = reinterpret_cast<const char*>(buffer.data() + payload_start);
        std::string payload(payload_ptr, static_cast<std::size_t>(payload_len));
        buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(total));
        deliver(authenticated, eid, std::move(payload));
        made_progress = true;
    }
}

std::vector<std::uint8_t> greeting(const std::string& magic1, const std::string& magic2) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(MAGIC_SIZE * 2);
    bytes.insert(bytes.end(), magic1.begin(), magic1.end());
    bytes.insert(bytes.end(), magic2.begin(), magic2.end());
    return bytes;
}

bool wait_readable(socket_t sock) {
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(sock, &read_set);
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
#ifdef _WIN32
    return ::select(0, &read_set, nullptr, nullptr, &timeout) > 0;
#else
    return ::select(sock + 1, &read_set, nullptr, nullptr, &timeout) > 0;
#endif
}

socket_t create_connected_socket(const std::string& host, std::uint16_t port) {
    ensure_socket_runtime();
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* result = nullptr;
    const std::string service = std::to_string(port);
    const int rc = getaddrinfo(host.c_str(), service.c_str(), &hints, &result);
    if (rc != 0) {
#ifdef _WIN32
        throw std::runtime_error("getaddrinfo failed: " + std::to_string(rc));
#else
        throw std::runtime_error(std::string("getaddrinfo failed: ") + gai_strerror(rc));
#endif
    }
    socket_t connected = INVALID_SOCKET_VALUE;
    for (addrinfo* it = result; it != nullptr; it = it->ai_next) {
        socket_t candidate = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (candidate == INVALID_SOCKET_VALUE) continue;
        if (::connect(candidate, it->ai_addr, static_cast<int>(it->ai_addrlen)) == 0) {
            connected = candidate;
            break;
        }
        close_socket(candidate);
    }
    freeaddrinfo(result);
    if (connected == INVALID_SOCKET_VALUE) throw std::runtime_error("could not connect to server");
    return connected;
}

} // namespace

class Server {
public:
    Server(std::string host, std::uint16_t port, py::object handshake_worker,
           py::object on_exchange, std::size_t simult_handshakes, std::size_t simult_exchanges)
        : host_(std::move(host)), port_(port),
          handshake_worker_(std::move(handshake_worker)), on_exchange_(std::move(on_exchange)),
          has_handshake_worker_(!handshake_worker_.is_none()), has_on_exchange_(!on_exchange_.is_none()),
          handshake_pool_(simult_handshakes), exchange_pool_(simult_exchanges) {
        ensure_socket_runtime();
        regenerate_magic();
    }

    ~Server() { stop(); }

    void start() {
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) throw std::runtime_error("server is already running");
        if (ever_started_) {
            running_.store(false);
            throw std::runtime_error("a stopped Server cannot be restarted; create a new Server object");
        }
        ever_started_ = true;
        try {
            addrinfo hints{};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            hints.ai_flags = AI_PASSIVE;
            addrinfo* result = nullptr;
            const std::string service = std::to_string(port_);
            const int rc = getaddrinfo(host_.empty() ? nullptr : host_.c_str(), service.c_str(), &hints, &result);
            if (rc != 0) {
#ifdef _WIN32
                throw std::runtime_error("getaddrinfo failed: " + std::to_string(rc));
#else
                throw std::runtime_error(std::string("getaddrinfo failed: ") + gai_strerror(rc));
#endif
            }
            socket_t listener = INVALID_SOCKET_VALUE;
            for (addrinfo* it = result; it != nullptr; it = it->ai_next) {
                socket_t candidate = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
                if (candidate == INVALID_SOCKET_VALUE) continue;
                int reuse = 1;
#ifdef _WIN32
                setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#else
                setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
                if (::bind(candidate, it->ai_addr, static_cast<int>(it->ai_addrlen)) == 0 && ::listen(candidate, SOMAXCONN) == 0) {
                    listener = candidate;
                    break;
                }
                close_socket(candidate);
            }
            freeaddrinfo(result);
            if (listener == INVALID_SOCKET_VALUE) throw std::runtime_error("could not bind/listen on the requested IP/port");
            listener_.store(listener);
            accept_thread_ = std::thread([this] { accept_loop(); });
        } catch (...) {
            running_.store(false);
            throw;
        }
    }

    void stop() {
        const bool was_running = running_.exchange(false);
        if (!was_running && !accept_thread_.joinable() && reader_threads_.empty()) {
            // Still stop the pools if startup failed or stop was called before start.
            handshake_pool_.stop();
            exchange_pool_.stop();
            return;
        }
        close_socket(listener_.exchange(INVALID_SOCKET_VALUE));
        std::vector<std::shared_ptr<Connection>> connections;
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            for (auto& c : connections_) connections.push_back(c);
        }
        for (auto& c : connections) {
            c->mark_closed();
            close_socket(c->sock.exchange(INVALID_SOCKET_VALUE));
        }
        if (accept_thread_.joinable() && accept_thread_.get_id() != std::this_thread::get_id()) accept_thread_.join();
        for (auto& entry : reader_threads_) {
            auto& t = entry.thread;
            if (t.joinable() && t.get_id() != std::this_thread::get_id()) t.join();
        }
        reader_threads_.clear();
        handshake_pool_.stop();
        exchange_pool_.stop();
        {
            std::lock_guard<std::mutex> lock(ids_mutex_);
            id_map_.clear();
            temp_map_.clear();
        }
    }

    std::optional<std::string> send_bytes(const std::string& cid, const std::string& payload,
                                          const std::optional<std::string>& eid) {
        auto conn = find_connection(cid);
        if (!conn) throw std::out_of_range("unknown client identifier (it may have disconnected or been authenticated)");
        return send_on_connection(conn, payload, eid);
    }

    std::optional<std::vector<std::uint8_t>> recv_bytes(const std::string& cid,
                                                        const std::optional<std::string>& eid,
                                                        const std::optional<double>& timeout) {
        auto conn = find_connection(cid);
        if (!conn) throw std::out_of_range("unknown client identifier");
        if (conn->is_authed.load() && !eid.has_value())
            throw std::invalid_argument("eid is required for recv() after authentication");
        if (!conn->is_authed.load() && eid.has_value())
            throw std::invalid_argument("eid cannot be specified before authentication");
        return conn->pop_message(eid, timeout);
    }

    bool auth_finished(const py::bytes& temp_cid_value, const py::bytes& new_cid_value,
                       const py::object& confirmation_value) {
        const std::string temp_cid = pybytes_to_string(temp_cid_value);
        const std::string new_cid = require_nonempty_bytes(new_cid_value, "new_cid");
        std::optional<std::vector<std::uint8_t>> confirmation_frame;
        if (!confirmation_value.is_none()) {
            if (!py::isinstance<py::bytes>(confirmation_value))
                throw py::type_error("confirmation_payload must be bytes or None");
            const std::string confirmation_payload = pybytes_to_string(py::cast<py::bytes>(confirmation_value));
            confirmation_frame = make_unauth_frame(magic1_, magic2_, confirmation_payload);
        }

        std::shared_ptr<Connection> conn;
        bool confirmation_send_failed = false;
        {
            std::lock_guard<std::mutex> ids_lock(ids_mutex_);
            auto temp_it = temp_map_.find(temp_cid);
            if (temp_it == temp_map_.end()) throw py::key_error("unknown temp_cid or authentication has already finished");
            if (id_map_.find(new_cid) != id_map_.end() ||
                (new_cid != temp_cid && temp_map_.find(new_cid) != temp_map_.end()))
                throw py::value_error("new_cid is already in use");
            conn = temp_it->second;
            // Serialize the state transition with all sends on this socket. When an optional
            // confirmation is provided, the connection switches to authenticated mode first,
            // then this one final pre-auth frame is emitted so the peer has a race-free signal.
            std::lock_guard<std::mutex> send_lock(conn->send_mutex);
            {
                std::lock_guard<std::mutex> identity_lock(conn->identity_mutex);
                conn->public_cid = new_cid;
                conn->is_authed.store(true);
            }
            temp_map_.erase(temp_it);
            id_map_.emplace(new_cid, conn);
            if (confirmation_frame.has_value()) {
                const socket_t s = conn->sock.load();
                confirmation_send_failed = s == INVALID_SOCKET_VALUE || conn->closed.load() ||
                    !socket_send_all(s, confirmation_frame->data(), confirmation_frame->size());
            }
        }
        if (confirmation_send_failed) {
            conn->mark_closed();
            close_socket(conn->sock.exchange(INVALID_SOCKET_VALUE));
            remove_connection(conn);
            throw std::runtime_error("failed to send authentication confirmation");
        }
        return true;
    }

    bool is_authed(const py::bytes& cid_value) {
        auto conn = find_connection(pybytes_to_string(cid_value));
        return conn && conn->is_authed.load();
    }

    void set_backpressure(const py::bytes& cid_value, bool enabled) {
        auto conn = find_connection(pybytes_to_string(cid_value));
        if (!conn) throw py::key_error("unknown client identifier");
        conn->backpressure.store(enabled);
    }

    void forget_exchange(const py::bytes& cid_value, const py::bytes& eid_value) {
        auto conn = find_connection(pybytes_to_string(cid_value));
        if (!conn) throw py::key_error("unknown client identifier");
        const std::string eid = pybytes_to_string(eid_value);
        if (eid.size() != EID_SIZE) throw py::value_error("eid must be exactly 8 bytes");
        {
            std::lock_guard<std::mutex> lock(conn->exchanges_mutex);
            conn->known_eids.erase(eid);
        }
        {
            std::lock_guard<std::mutex> lock(conn->message_mutex);
            conn->exchange_messages.erase(eid);
        }
    }

    py::bytes magic1() const { return string_to_pybytes(magic1_); }
    py::bytes magic2() const { return string_to_pybytes(magic2_); }

private:
    void regenerate_magic() {
        magic1_ = random_bytes(MAGIC_SIZE);
        do { magic2_ = random_bytes(MAGIC_SIZE); } while (magic2_ == magic1_);
    }

    std::shared_ptr<Connection> find_connection(const std::string& cid) {
        std::lock_guard<std::mutex> lock(ids_mutex_);
        auto it = id_map_.find(cid);
        if (it != id_map_.end()) return it->second;
        auto ti = temp_map_.find(cid);
        if (ti != temp_map_.end()) return ti->second;
        return nullptr;
    }

    std::optional<std::string> send_on_connection(const std::shared_ptr<Connection>& conn,
                                                  const std::string& payload,
                                                  const std::optional<std::string>& supplied_eid) {
        std::lock_guard<std::mutex> send_lock(conn->send_mutex);
        if (conn->closed.load() || conn->sock.load() == INVALID_SOCKET_VALUE) throw std::runtime_error("client is disconnected");
        std::vector<std::uint8_t> frame;
        std::optional<std::string> generated_eid;
        if (!conn->is_authed.load()) {
            if (supplied_eid.has_value()) throw std::invalid_argument("eid cannot be specified before authentication");
            frame = make_unauth_frame(magic1_, magic2_, payload);
        } else {
            std::string eid;
            if (supplied_eid.has_value()) {
                eid = *supplied_eid;
                std::lock_guard<std::mutex> lock(conn->exchanges_mutex);
                conn->known_eids.insert(eid);
            } else {
                for (int attempt = 0; attempt < 32; ++attempt) {
                    eid = random_bytes(EID_SIZE);
                    std::lock_guard<std::mutex> lock(conn->exchanges_mutex);
                    if (conn->known_eids.insert(eid).second) break;
                    eid.clear();
                }
                if (eid.empty()) throw std::runtime_error("could not generate a unique exchange id");
                generated_eid = eid;
            }
            frame = make_auth_frame(magic1_, magic2_, eid, payload);
        }
        const socket_t s = conn->sock.load();
        const bool ok = s != INVALID_SOCKET_VALUE && !conn->closed.load() &&
            socket_send_all(s, frame.data(), frame.size());
        if (!ok) {
            conn->mark_closed();
            close_socket(conn->sock.exchange(INVALID_SOCKET_VALUE));
            throw std::runtime_error("socket send failed; client may have disconnected");
        }
        return generated_eid;
    }

    void accept_loop() {
        while (running_.load()) {
            const socket_t listener = listener_.load();
            if (listener == INVALID_SOCKET_VALUE) break;
            sockaddr_storage addr{};
#ifdef _WIN32
            int addr_len = sizeof(addr);
#else
            socklen_t addr_len = sizeof(addr);
#endif
            socket_t accepted = ::accept(listener, reinterpret_cast<sockaddr*>(&addr), &addr_len);
            if (accepted == INVALID_SOCKET_VALUE) {
                if (running_.load()) std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            reap_finished_readers();
            if (!running_.load()) { close_socket(accepted); break; }
            auto conn = std::make_shared<Connection>();
            conn->sock.store(accepted);
            conn->is_server_side = true;
            conn->magic1 = magic1_;
            conn->magic2 = magic2_;
            {
                std::lock_guard<std::mutex> lock(ids_mutex_);
                do { conn->temp_cid = random_bytes(EID_SIZE); }
                while (id_map_.count(conn->temp_cid) || temp_map_.count(conn->temp_cid));
                temp_map_.emplace(conn->temp_cid, conn);
            }
            const auto intro = greeting(magic1_, magic2_);
            if (!socket_send_all(accepted, intro.data(), intro.size())) {
                conn->mark_closed();
                close_socket(conn->sock.exchange(INVALID_SOCKET_VALUE));
                remove_connection(conn);
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                connections_.push_back(conn);
            }
            reader_threads_.push_back(ReaderThread{conn, std::thread([this, conn] { reader_loop(conn); })});
        }
    }

    void reader_loop(const std::shared_ptr<Connection>& conn) {
        std::vector<std::uint8_t> buffer;
        buffer.reserve(8192);
        std::array<std::uint8_t, RECV_CHUNK_SIZE> chunk{};
        while (running_.load() && !conn->closed.load()) {
            if (conn->backpressure.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue; // no recv() calls while backpressure is active
            }
            const socket_t s = conn->sock.load();
            if (s == INVALID_SOCKET_VALUE) break;
            if (!wait_readable(s)) continue;
            if (conn->backpressure.load()) continue;
#ifdef _WIN32
            const int n = ::recv(s, reinterpret_cast<char*>(chunk.data()), static_cast<int>(chunk.size()), 0);
#else
            const ssize_t n = ::recv(s, chunk.data(), chunk.size(), 0);
#endif
            if (n == 0) break;
            if (n < 0) {
                if (!running_.load() || conn->closed.load()) break;
                if (socket_error_retryable(last_socket_error())) continue;
                break;
            }
            buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + n);
            const std::size_t hard_cap = MAX_AUTH_PAYLOAD + RECV_CHUNK_SIZE + MAGIC_SIZE * 3 + AUTH_HEADER_SIZE + EID_SIZE;
            if (buffer.size() > hard_cap) {
                // A syntactically valid max-size frame fits under this cap. A larger rolling buffer
                // is not useful and could indicate an invalid or malicious length prefix.
                conn->mark_closed();
                break;
            }
            parse_frames(conn, buffer, [this, conn](bool authenticated, const std::string& eid, std::string payload) {
                deliver_message(conn, authenticated, eid, std::move(payload));
            });
        }
        conn->mark_closed();
        close_socket(conn->sock.exchange(INVALID_SOCKET_VALUE));
        remove_connection(conn);
        conn->reader_done.store(true);
    }

    void deliver_message(const std::shared_ptr<Connection>& conn, bool authenticated,
                         const std::string& eid, std::string payload) {
        if (!authenticated) {
            conn->push_message(std::string(), std::vector<std::uint8_t>(payload.begin(), payload.end()), false);
            if (conn->is_server_side && !conn->handshake_triggered.exchange(true) && has_handshake_worker_) {
                const std::string temp = conn->temp_cid;
                handshake_pool_.submit([this, temp] { invoke_handshake(temp); });
            }
            return;
        }
        bool is_new = false;
        {
            std::lock_guard<std::mutex> lock(conn->exchanges_mutex);
            is_new = conn->known_eids.insert(eid).second;
        }
        conn->push_message(eid, std::vector<std::uint8_t>(payload.begin(), payload.end()), true);
        if (is_new && has_on_exchange_) {
            const std::string cid = conn->current_id();
            exchange_pool_.submit([this, cid, eid] { invoke_exchange(cid, eid); });
        }
    }

    void invoke_handshake(const std::string& temp_cid) {
        py::gil_scoped_acquire acquire;
        try {
            handshake_worker_(string_to_pybytes(temp_cid));
        } catch (py::error_already_set& e) {
            std::cerr << "[network] handshake_worker raised: " << e.what() << '\n';
            e.restore();
            PyErr_WriteUnraisable(Py_None);
            PyErr_Clear();
        } catch (const std::exception& e) {
            std::cerr << "[network] handshake_worker failed: " << e.what() << '\n';
        }
    }

    void invoke_exchange(const std::string& cid, const std::string& eid) {
        py::gil_scoped_acquire acquire;
        try {
            on_exchange_(string_to_pybytes(cid), string_to_pybytes(eid));
        } catch (py::error_already_set& e) {
            std::cerr << "[network] on_exchange raised: " << e.what() << '\n';
            e.restore();
            PyErr_WriteUnraisable(Py_None);
            PyErr_Clear();
        } catch (const std::exception& e) {
            std::cerr << "[network] on_exchange failed: " << e.what() << '\n';
        }
    }

    struct ReaderThread {
        std::shared_ptr<Connection> connection;
        std::thread thread;
    };

    void reap_finished_readers() {
        for (auto it = reader_threads_.begin(); it != reader_threads_.end();) {
            if (it->connection->reader_done.load()) {
                if (it->thread.joinable()) it->thread.join();
                it = reader_threads_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void remove_connection(const std::shared_ptr<Connection>& conn) {
        std::lock_guard<std::mutex> lock(ids_mutex_);
        auto it = temp_map_.find(conn->temp_cid);
        if (it != temp_map_.end() && it->second == conn) temp_map_.erase(it);
        std::lock_guard<std::mutex> identity_lock(conn->identity_mutex);
        auto ci = id_map_.find(conn->public_cid);
        if (ci != id_map_.end() && ci->second == conn) id_map_.erase(ci);
        {
            std::lock_guard<std::mutex> connections_lock(connections_mutex_);
            connections_.erase(std::remove(connections_.begin(), connections_.end(), conn), connections_.end());
        }
    }

    std::string host_;
    std::uint16_t port_;
    std::string magic1_;
    std::string magic2_;
    py::object handshake_worker_;
    py::object on_exchange_;
    const bool has_handshake_worker_;
    const bool has_on_exchange_;
    FifoExecutor handshake_pool_;
    FifoExecutor exchange_pool_;
    std::atomic<bool> running_{false};
    bool ever_started_ = false;
    std::atomic<socket_t> listener_{INVALID_SOCKET_VALUE};
    std::thread accept_thread_;
    std::vector<ReaderThread> reader_threads_;
    std::mutex connections_mutex_;
    std::vector<std::shared_ptr<Connection>> connections_;
    std::mutex ids_mutex_;
    std::map<std::string, std::shared_ptr<Connection>> id_map_;
    std::map<std::string, std::shared_ptr<Connection>> temp_map_;
};

class Client {
public:
    Client(std::string host, std::uint16_t port, py::object on_exchange, std::size_t simult_exchanges)
        : host_(std::move(host)), port_(port), on_exchange_(std::move(on_exchange)),
          has_on_exchange_(!on_exchange_.is_none()), exchange_pool_(simult_exchanges) {
        ensure_socket_runtime();
    }
    ~Client() { disconnect(); }

    void connect() {
        if (connected_.load()) throw std::runtime_error("client is already connected");
        if (ever_connected_) throw std::runtime_error("a disconnected Client cannot reconnect; create a new Client object");
        ever_connected_ = true;
        socket_t s = create_connected_socket(host_, port_);
        std::array<std::uint8_t, MAGIC_SIZE * 2> intro{};
        if (!socket_recv_exact(s, intro.data(), intro.size())) {
            close_socket(s);
            throw std::runtime_error("server disconnected before sending its framing magic");
        }
        magic1_.assign(reinterpret_cast<const char*>(intro.data()), MAGIC_SIZE);
        magic2_.assign(reinterpret_cast<const char*>(intro.data() + MAGIC_SIZE), MAGIC_SIZE);
        if (magic1_ == magic2_) {
            close_socket(s);
            throw std::runtime_error("server supplied invalid framing magic values");
        }
        conn_ = std::make_shared<Connection>();
        conn_->sock.store(s);
        conn_->is_server_side = false;
        conn_->magic1 = magic1_;
        conn_->magic2 = magic2_;
        connected_.store(true);
        reader_thread_ = std::thread([this] { reader_loop(); });
    }

    void disconnect() {
        connected_.store(false);
        auto conn = conn_;
        if (conn) {
            conn->mark_closed();
            close_socket(conn->sock.exchange(INVALID_SOCKET_VALUE));
        }
        if (reader_thread_.joinable() && reader_thread_.get_id() != std::this_thread::get_id()) reader_thread_.join();
        exchange_pool_.stop();
    }

    std::optional<std::string> send_bytes(const std::string& payload,
                                          const std::optional<std::string>& eid) {
        ensure_connected();
        return send_on_connection(payload, eid);
    }

    std::optional<std::vector<std::uint8_t>> recv_bytes(const std::optional<std::string>& eid,
                                                        const std::optional<double>& timeout) {
        ensure_connected();
        if (conn_->is_authed.load() && !eid.has_value())
            throw std::invalid_argument("eid is required for recv() after authentication");
        if (!conn_->is_authed.load() && eid.has_value())
            throw std::invalid_argument("eid cannot be specified before authentication");
        return conn_->pop_message(eid, timeout);
    }

    bool auth_finished(const py::bytes& new_cid_value) {
        ensure_connected();
        const std::string new_cid = require_nonempty_bytes(new_cid_value, "new_cid");
        std::lock_guard<std::mutex> send_lock(conn_->send_mutex);
        {
            std::lock_guard<std::mutex> lock(conn_->identity_mutex);
            conn_->public_cid = new_cid;
            conn_->is_authed.store(true);
        }
        return true;
    }

    bool is_authed() const { return conn_ && conn_->is_authed.load(); }

    void set_backpressure(bool enabled) {
        ensure_connected();
        conn_->backpressure.store(enabled);
    }

    void forget_exchange(const py::bytes& eid_value) {
        ensure_connected();
        const std::string eid = pybytes_to_string(eid_value);
        if (eid.size() != EID_SIZE) throw py::value_error("eid must be exactly 8 bytes");
        {
            std::lock_guard<std::mutex> lock(conn_->exchanges_mutex);
            conn_->known_eids.erase(eid);
        }
        {
            std::lock_guard<std::mutex> lock(conn_->message_mutex);
            conn_->exchange_messages.erase(eid);
        }
    }

    py::bytes magic1() const { return string_to_pybytes(magic1_); }
    py::bytes magic2() const { return string_to_pybytes(magic2_); }
    py::object cid() const {
        if (!conn_ || !conn_->is_authed.load()) return py::none();
        std::lock_guard<std::mutex> lock(conn_->identity_mutex);
        return string_to_pybytes(conn_->public_cid);
    }

private:
    void ensure_connected() const {
        if (!connected_.load() || !conn_ || conn_->closed.load()) throw std::runtime_error("client is not connected");
    }

    std::optional<std::string> send_on_connection(const std::string& payload,
                                                  const std::optional<std::string>& supplied_eid) {
        auto conn = conn_;
        std::lock_guard<std::mutex> send_lock(conn->send_mutex);
        if (conn->closed.load() || conn->sock.load() == INVALID_SOCKET_VALUE) throw std::runtime_error("client is disconnected");
        std::vector<std::uint8_t> frame;
        std::optional<std::string> generated_eid;
        if (!conn->is_authed.load()) {
            if (supplied_eid.has_value()) throw std::invalid_argument("eid cannot be specified before authentication");
            frame = make_unauth_frame(magic1_, magic2_, payload);
        } else {
            std::string eid;
            if (supplied_eid.has_value()) {
                eid = *supplied_eid;
                std::lock_guard<std::mutex> lock(conn->exchanges_mutex);
                conn->known_eids.insert(eid);
            } else {
                for (int attempt = 0; attempt < 32; ++attempt) {
                    eid = random_bytes(EID_SIZE);
                    std::lock_guard<std::mutex> lock(conn->exchanges_mutex);
                    if (conn->known_eids.insert(eid).second) break;
                    eid.clear();
                }
                if (eid.empty()) throw std::runtime_error("could not generate a unique exchange id");
                generated_eid = eid;
            }
            frame = make_auth_frame(magic1_, magic2_, eid, payload);
        }
        const socket_t s = conn->sock.load();
        const bool ok = s != INVALID_SOCKET_VALUE && !conn->closed.load() &&
            socket_send_all(s, frame.data(), frame.size());
        if (!ok) {
            conn->mark_closed();
            close_socket(conn->sock.exchange(INVALID_SOCKET_VALUE));
            throw std::runtime_error("socket send failed; server may have disconnected");
        }
        return generated_eid;
    }

    void reader_loop() {
        std::vector<std::uint8_t> buffer;
        buffer.reserve(8192);
        std::array<std::uint8_t, RECV_CHUNK_SIZE> chunk{};
        while (connected_.load() && conn_ && !conn_->closed.load()) {
            if (conn_->backpressure.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            const socket_t s = conn_->sock.load();
            if (s == INVALID_SOCKET_VALUE) break;
            if (!wait_readable(s)) continue;
            if (conn_->backpressure.load()) continue;
#ifdef _WIN32
            const int n = ::recv(s, reinterpret_cast<char*>(chunk.data()), static_cast<int>(chunk.size()), 0);
#else
            const ssize_t n = ::recv(s, chunk.data(), chunk.size(), 0);
#endif
            if (n == 0) break;
            if (n < 0) {
                if (!connected_.load() || conn_->closed.load()) break;
                if (socket_error_retryable(last_socket_error())) continue;
                break;
            }
            buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + n);
            const std::size_t hard_cap = MAX_AUTH_PAYLOAD + RECV_CHUNK_SIZE + MAGIC_SIZE * 3 + AUTH_HEADER_SIZE + EID_SIZE;
            if (buffer.size() > hard_cap) { conn_->mark_closed(); break; }
            parse_frames(conn_, buffer, [this](bool authenticated, const std::string& eid, std::string payload) {
                deliver_message(authenticated, eid, std::move(payload));
            });
        }
        connected_.store(false);
        if (conn_) {
            conn_->mark_closed();
            close_socket(conn_->sock.exchange(INVALID_SOCKET_VALUE));
        }
    }

    void deliver_message(bool authenticated, const std::string& eid, std::string payload) {
        if (!conn_) return;
        if (!authenticated) {
            conn_->push_message(std::string(), std::vector<std::uint8_t>(payload.begin(), payload.end()), false);
            return;
        }
        bool is_new = false;
        {
            std::lock_guard<std::mutex> lock(conn_->exchanges_mutex);
            is_new = conn_->known_eids.insert(eid).second;
        }
        conn_->push_message(eid, std::vector<std::uint8_t>(payload.begin(), payload.end()), true);
        if (is_new && has_on_exchange_) {
            const std::string cid = conn_->current_id();
            exchange_pool_.submit([this, cid, eid] { invoke_exchange(cid, eid); });
        }
    }

    void invoke_exchange(const std::string& cid, const std::string& eid) {
        py::gil_scoped_acquire acquire;
        try {
            on_exchange_(string_to_pybytes(cid), string_to_pybytes(eid));
        } catch (py::error_already_set& e) {
            std::cerr << "[network] on_exchange raised: " << e.what() << '\n';
            e.restore();
            PyErr_WriteUnraisable(Py_None);
            PyErr_Clear();
        } catch (const std::exception& e) {
            std::cerr << "[network] on_exchange failed: " << e.what() << '\n';
        }
    }

    std::string host_;
    std::uint16_t port_;
    py::object on_exchange_;
    const bool has_on_exchange_;
    FifoExecutor exchange_pool_;
    std::shared_ptr<Connection> conn_;
    std::string magic1_;
    std::string magic2_;
    std::atomic<bool> connected_{false};
    bool ever_connected_ = false;
    std::thread reader_thread_;
};

PYBIND11_MODULE(network, module) {
    module.doc() = "Networking v2.0 TCP messaging module";
    module.attr("MAX_UNAUTH_PAYLOAD") = MAX_UNAUTH_PAYLOAD;
    module.attr("MAX_AUTH_PAYLOAD") = MAX_AUTH_PAYLOAD;

    py::class_<Server>(module, "Server")
        .def(py::init<std::string, std::uint16_t, py::object, py::object, std::size_t, std::size_t>(),
             py::arg("host"), py::arg("port"), py::arg("handshake_worker") = py::none(),
             py::arg("on_exchange") = py::none(), py::arg("simult_handshakes") = 4,
             py::arg("simult_exchanges") = 4)
        .def("start", [](Server& self) { self.start(); }, "Start listening for incoming connections.")
        .def("stop", [](Server& self) { py::gil_scoped_release release; self.stop(); }, "Stop the server and wait for background work to finish.")
        .def("send", [](Server& self, const py::bytes& cid_value, const py::bytes& payload_value, const py::object& eid_value) -> py::object {
            const std::string cid = pybytes_to_string(cid_value);
            const std::string payload = pybytes_to_string(payload_value);
            const auto eid = parse_eid_object(eid_value);
            std::optional<std::string> result;
            { py::gil_scoped_release release; result = self.send_bytes(cid, payload, eid); }
            if (result.has_value()) return string_to_pybytes(*result);
            return py::none();
        }, py::arg("cid"), py::arg("payload"), py::arg("eid") = py::none(),
           "Send bytes. With eid=None after auth, starts a new exchange and returns its 8-byte eid; otherwise returns None.")
        .def("recv", [](Server& self, const py::bytes& cid_value, const py::object& eid_value, const py::object& timeout_value) {
            const std::string cid = pybytes_to_string(cid_value);
            const auto eid = parse_eid_object(eid_value);
            const auto timeout = parse_timeout(timeout_value);
            std::optional<std::vector<std::uint8_t>> result;
            { py::gil_scoped_release release; result = self.recv_bytes(cid, eid, timeout); }
            if (!result.has_value()) return py::object(py::none());
            if (result->empty()) return py::object(py::bytes("", 0));
            return py::object(py::bytes(reinterpret_cast<const char*>(result->data()), result->size()));
        }, py::arg("cid"), py::arg("eid") = py::none(), py::arg("timeout") = py::none(),
           "Receive handshake bytes before auth or bytes from a specific authenticated exchange. Returns None on timeout/closure.")
        .def("auth_finished", &Server::auth_finished, py::arg("temp_cid"), py::arg("new_cid"),
             py::arg("confirmation_payload") = py::none())
        .def("is_authed", &Server::is_authed, py::arg("cid"))
        .def("set_backpressure", &Server::set_backpressure, py::arg("cid"), py::arg("enabled"))
        .def("forget_exchange", &Server::forget_exchange, py::arg("cid"), py::arg("eid"),
             "Forget a completed exchange locally so its id and any queued messages can be released.")
        .def_property_readonly("MAGIC1", &Server::magic1)
        .def_property_readonly("MAGIC2", &Server::magic2)
        .def("__enter__", [](Server& self) -> Server& { self.start(); return self; }, py::return_value_policy::reference_internal)
        .def("__exit__", [](Server& self, py::object, py::object, py::object) { py::gil_scoped_release release; self.stop(); })
        .def("__del__", [](Server& self) { py::gil_scoped_release release; self.stop(); });

    py::class_<Client>(module, "Client")
        .def(py::init<std::string, std::uint16_t, py::object, std::size_t>(),
             py::arg("host"), py::arg("port"), py::arg("on_exchange") = py::none(),
             py::arg("simult_exchanges") = 4)
        .def("connect", [](Client& self) { py::gil_scoped_release release; self.connect(); }, "Connect and receive the server's 16-byte framing greeting.")
        .def("disconnect", [](Client& self) { py::gil_scoped_release release; self.disconnect(); })
        .def("send", [](Client& self, const py::bytes& payload_value, const py::object& eid_value) -> py::object {
            const std::string payload = pybytes_to_string(payload_value);
            const auto eid = parse_eid_object(eid_value);
            std::optional<std::string> result;
            { py::gil_scoped_release release; result = self.send_bytes(payload, eid); }
            if (result.has_value()) return string_to_pybytes(*result);
            return py::none();
        }, py::arg("payload"), py::arg("eid") = py::none())
        .def("recv", [](Client& self, const py::object& eid_value, const py::object& timeout_value) {
            const auto eid = parse_eid_object(eid_value);
            const auto timeout = parse_timeout(timeout_value);
            std::optional<std::vector<std::uint8_t>> result;
            { py::gil_scoped_release release; result = self.recv_bytes(eid, timeout); }
            if (!result.has_value()) return py::object(py::none());
            if (result->empty()) return py::object(py::bytes("", 0));
            return py::object(py::bytes(reinterpret_cast<const char*>(result->data()), result->size()));
        }, py::arg("eid") = py::none(), py::arg("timeout") = py::none())
        .def("auth_finished", &Client::auth_finished, py::arg("new_cid"),
             "Mark the local connection authenticated after the application handshake has succeeded.")
        .def_property_readonly("is_authed", &Client::is_authed)
        .def_property_readonly("cid", &Client::cid)
        .def_property_readonly("MAGIC1", &Client::magic1)
        .def_property_readonly("MAGIC2", &Client::magic2)
        .def("set_backpressure", &Client::set_backpressure, py::arg("enabled"))
        .def("forget_exchange", &Client::forget_exchange, py::arg("eid"),
             "Forget a completed exchange locally so its id and any queued messages can be released.")
        .def("__enter__", [](Client& self) -> Client& { self.connect(); return self; }, py::return_value_policy::reference_internal)
        .def("__exit__", [](Client& self, py::object, py::object, py::object) { py::gil_scoped_release release; self.disconnect(); })
        .def("__del__", [](Client& self) { py::gil_scoped_release release; self.disconnect(); });
}
