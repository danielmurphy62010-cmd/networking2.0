use async_channel::{Receiver, Sender, TrySendError};
use rand::{rngs::OsRng, RngCore};
use std::collections::{HashMap, VecDeque};
pub use futures::future::BoxFuture;
use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, sleep_until, timeout, timeout_at, Instant as TokioInstant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
pub const MAX_UNAUTH_PAYLOAD: usize = 65_535;
pub const MAX_AUTH_PAYLOAD: usize = 33_554_432;
pub const QUEUE_LIMIT: usize = 16;
const MAGIC_N: usize = 8;
const EID_N: usize = 8;
const UNAUTH_HEAD: usize = 2;
const AUTH_HEAD: usize = 5;
const MAX_INPUT_BUFFER: usize = 32 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 200;
const MAX_UNAUTH_CONNECTIONS: usize = 128;
const MAX_CONNECTIONS_PER_PEER: usize = 64;
const MAX_PEER_BUCKETS: usize = 4096;
const MAX_NEW_CONNECTIONS_PER_PEER_PER_MINUTE: usize = 120;
const MAX_ACTIVE_EIDS_PER_CONNECTION: usize = 2048;
const MAX_READ_PER_TICK: usize = 64 * 1024;
const MAX_WRITE_PER_TICK: usize = 64 * 1024;
const MAX_ACCEPT_PER_TICK: usize = 32;
const MAX_PARSE_FRAMES_PER_CALL: usize = 32;
const MAX_PARSE_STEPS_PER_CALL: usize = 128;
const MAX_GLOBAL_BUFFERED_BYTES: usize = 512 * 1024 * 1024;
const MAX_CONNECTION_BUFFERED_BYTES: usize = 128 * 1024 * 1024;
const MAX_POOL_WORKERS: usize = 64;
const MAX_PENDING_CALLBACKS_MIN: usize = 32;
const MAX_PENDING_CALLBACKS_MAX: usize = 1024;
const MAX_CID_BYTES: usize = 256;
const UNAUTH_TIMEOUT: Duration = Duration::from_secs(30);
const EID_TTL: Duration = Duration::from_secs(60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const GREETING_TIMEOUT: Duration = Duration::from_secs(5);
const READ_CHUNK: usize = 16 * 1024;
pub type Eid = [u8; EID_N];
type Job = Box<dyn FnOnce() -> BoxFuture<'static, ()> + Send + 'static>;
type DeliverFn = Arc<dyn Fn(Arc<Connection>, bool, Eid, Vec<u8>, Lease) -> bool + Send + Sync>;
#[derive(Debug, Error)]
pub enum BackendError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("unknown connection ID")]
    UnknownCid,
    #[error("unknown temporary connection ID")]
    UnknownTempCid,
    #[error("connection is closed")]
    ConnectionClosed,
    #[error("connection is not authenticated")]
    NotAuthenticated,
    #[error("operation is only available before authentication")]
    AlreadyAuthenticated,
    #[error("send queue is full")]
    QueueFull,
    #[error("buffer budget exhausted")]
    BufferBudgetExhausted,
    #[error("too many active EIDs for this connection")]
    EidLimit,
    #[error("server has already been stopped")]
    Stopped,
    #[error("server is already running")]
    AlreadyRunning,
    #[error("connection failed or timed out")]
    ConnectFailed,
}
pub type Result<T> = std::result::Result<T, BackendError>;
fn mutex_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}
fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|poisoned| poisoned.into_inner())
}
fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| BackendError::InvalidArgument("operating-system random source failed".into()))?;
    Ok(bytes)
}
fn random_vec(n: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; n];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| BackendError::InvalidArgument("operating-system random source failed".into()))?;
    Ok(bytes)
}
fn tune_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let socket = socket2::SockRef::from(stream);
    let _ = socket.set_recv_buffer_size(64 * 1024);
    let _ = socket.set_send_buffer_size(64 * 1024);
    #[cfg(unix)]
    let _ = socket.set_keepalive(true);
}
fn bind_listener(address: std::net::SocketAddr) -> io::Result<TcpListener> {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(
        domain,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    let socket_address: socket2::SockAddr = address.into();
    socket.bind(&socket_address)?;
    socket.listen(1024)?;
    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener)
}
#[derive(Debug)]
struct Quota {
    limit: usize,
    used: AtomicUsize,
}
impl Quota {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
        })
    }
    fn acquire(&self, amount: usize) -> bool {
        if amount == 0 {
            return true;
        }
        if amount > self.limit {
            return false;
        }
        let mut current = self.used.load(Ordering::Relaxed);
        loop {
            if current > self.limit - amount {
                return false;
            }
            match self.used.compare_exchange_weak(
                current,
                current + amount,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }
    fn release(&self, amount: usize) {
        if amount != 0 {
            self.used.fetch_sub(amount, Ordering::AcqRel);
        }
    }
}
struct Lease {
    global: Arc<Quota>,
    local: Arc<Quota>,
    amount: usize,
}
impl Lease {
    fn new(global: &Arc<Quota>, local: &Arc<Quota>, amount: usize) -> Option<Self> {
        if !global.acquire(amount) {
            return None;
        }
        if !local.acquire(amount) {
            global.release(amount);
            return None;
        }
        Some(Self {
            global: Arc::clone(global),
            local: Arc::clone(local),
            amount,
        })
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.local.release(self.amount);
        self.global.release(self.amount);
    }
}
struct Message {
    eid: Eid,
    payload: Vec<u8>,
    authed: bool,
    _memory: Lease,
}
struct Pending {
    payload: Vec<u8>,
    eid: Eid,
    authed: bool,
    _memory: Lease,
}
#[derive(Default)]
struct ConnectionState {
    recvq: VecDeque<Message>,
    sendq: VecDeque<Pending>,
    eid_activity: HashMap<Eid, Instant>,
}
struct Connection {
    server_side: bool,
    authed: AtomicBool,
    closed: AtomicBool,
    backpressure: AtomicBool,
    handshake_started: AtomicBool,
    disconnect_notified: AtomicBool,
    temp_cid: Vec<u8>,
    cid: RwLock<Vec<u8>>,
    peer: Option<IpAddr>,
    connect_time: Instant,
    connection_id: u64,
    state: Mutex<ConnectionState>,
    last_cleanup: Mutex<Instant>,
    input_global: Arc<Quota>,
    local_memory: Arc<Quota>,
    cancel: CancellationToken,
    recv_notify: tokio::sync::Notify,
    send_notify: tokio::sync::Notify,
    room_notify: tokio::sync::Notify,
    io_notify: tokio::sync::Notify,
}
impl Connection {
    fn new(
        global_memory: Arc<Quota>,
        server_side: bool,
        connection_id: u64,
        temp_cid: Vec<u8>,
        peer: Option<IpAddr>,
    ) -> Arc<Self> {
        Arc::new(Self {
            server_side,
            authed: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            backpressure: AtomicBool::new(false),
            handshake_started: AtomicBool::new(false),
            disconnect_notified: AtomicBool::new(false),
            temp_cid,
            cid: RwLock::new(Vec::new()),
            peer,
            connect_time: Instant::now(),
            connection_id,
            state: Mutex::new(ConnectionState::default()),
            last_cleanup: Mutex::new(Instant::now()),
            input_global: global_memory,
            local_memory: Quota::new(MAX_CONNECTION_BUFFERED_BYTES),
            cancel: CancellationToken::new(),
            recv_notify: tokio::sync::Notify::new(),
            send_notify: tokio::sync::Notify::new(),
            room_notify: tokio::sync::Notify::new(),
            io_notify: tokio::sync::Notify::new(),
        })
    }
    fn touch_eid(&self, eid: Eid) -> EidTouch {
        if self.closed.load(Ordering::Acquire) {
            return EidTouch::Closed;
        }
        let now = Instant::now();
        let mut state = mutex_lock(&self.state);
        if let Some(last) = state.eid_activity.get_mut(&eid) {
            *last = now;
            return EidTouch::Existing;
        }
        state.eid_activity.retain(|_, last| now.saturating_duration_since(*last) < EID_TTL);
        if state.eid_activity.len() >= MAX_ACTIVE_EIDS_PER_CONNECTION {
            return EidTouch::Limit;
        }
        state.eid_activity.insert(eid, now);
        EidTouch::Fresh
    }
    fn enqueue(&self, pending: Pending) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(BackendError::ConnectionClosed);
        }
        let mut state = mutex_lock(&self.state);
        if self.closed.load(Ordering::Acquire) {
            return Err(BackendError::ConnectionClosed);
        }
        if state.sendq.len() >= QUEUE_LIMIT {
            return Err(BackendError::QueueFull);
        }
        state.sendq.push_back(pending);
        drop(state);
        self.send_notify.notify_one();
        Ok(())
    }
    fn queue_pending(&self, payload: Vec<u8>, eid: Eid, authed: bool) -> Result<()> {
        let max_payload = if authed { MAX_AUTH_PAYLOAD } else { MAX_UNAUTH_PAYLOAD };
        if payload.len() > max_payload {
            return Err(BackendError::InvalidArgument(if authed {
                "payload exceeds 25-bit length limit".into()
            } else {
                "handshake payload exceeds 65535 bytes".into()
            }));
        }
        let amount = payload.len() + std::mem::size_of::<Pending>() + 32;
        let memory = Lease::new(&self.input_global, &self.local_memory, amount)
            .ok_or(BackendError::BufferBudgetExhausted)?;
        self.enqueue(Pending {
            payload,
            eid,
            authed,
            _memory: memory,
        })
    }
    fn has_recv_room(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
            && mutex_lock(&self.state).recvq.len() < QUEUE_LIMIT
    }
    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancel.cancel();
        {
            let mut state = mutex_lock(&self.state);
            state.recvq.clear();
            state.sendq.clear();
            state.eid_activity.clear();
        }
        self.recv_notify.notify_waiters();
        self.send_notify.notify_waiters();
        self.room_notify.notify_waiters();
        self.io_notify.notify_waiters();
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EidTouch {
    Fresh,
    Existing,
    Limit,
    Closed,
}
struct InputBuffer {
    data: Vec<u8>,
    memory: Option<Lease>,
    extra_memory: Option<Lease>,
}
impl InputBuffer {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            memory: None,
            extra_memory: None,
        }
    }
    fn ensure_capacity(&mut self, conn: &Connection, required: usize) -> bool {
        if required > MAX_INPUT_BUFFER {
            return false;
        }
        if required <= self.data.capacity() {
            return true;
        }
        let mut target = self.data.capacity().max(4096);
        while target < required {
            let next = if target > MAX_INPUT_BUFFER / 2 {
                MAX_INPUT_BUFFER
            } else {
                target * 2
            };
            if next <= target {
                return false;
            }
            target = next;
        }
        self.reallocate(conn, target)
    }
    fn reallocate(&mut self, conn: &Connection, target: usize) -> bool {
        if target > MAX_INPUT_BUFFER {
            return false;
        }
        let target = target.max(self.data.len());
        let Some(new_memory) = Lease::new(&conn.input_global, &conn.local_memory, target) else {
            return false;
        };
        let mut replacement = Vec::new();
        if replacement
            .try_reserve_exact(target)
            .is_err()
        {
            return false;
        }
        replacement.extend_from_slice(&self.data);
        let actual_capacity = replacement.capacity();
        let extra_memory = if actual_capacity > target {
            match Lease::new(
                &conn.input_global,
                &conn.local_memory,
                actual_capacity - target,
            ) {
                Some(lease) => Some(lease),
                None => return false,
            }
        } else {
            None
        };
        self.data = replacement;
        self.memory = Some(new_memory);
        self.extra_memory = extra_memory;
        true
    }
    fn compact(&mut self, conn: &Connection, consumed: usize) {
        if consumed >= self.data.len() {
            self.data.clear();
        } else if consumed != 0 {
            self.data.drain(..consumed);
        }
        if self.data.is_empty() && self.data.capacity() > 256 * 1024 {
            self.data = Vec::new();
            self.memory = None;
            self.extra_memory = None;
            return;
        }
        if self.data.capacity() > 1024 * 1024 && self.data.len() < self.data.capacity() / 8 {
            let target = 4096usize.max(self.data.len().saturating_mul(2));
            if target < self.data.capacity() {
                let _ = self.reallocate(conn, target);
            }
        }
    }
}
fn find_bytes(haystack: &[u8], marker: &[u8; MAGIC_N], start: usize) -> Option<usize> {
    if start > haystack.len() || haystack.len().saturating_sub(start) < MAGIC_N {
        return None;
    }
    haystack[start..]
        .windows(MAGIC_N)
        .position(|window| window == marker)
        .map(|offset| start + offset)
}
fn suffix_prefix_len(data: &[u8], marker: &[u8; MAGIC_N]) -> usize {
    let max = data.len().min(MAGIC_N - 1);
    for keep in (1..=max).rev() {
        if data[data.len() - keep..] == marker[..keep] {
            return keep;
        }
    }
    0
}
fn resync_after_malformed(data: &[u8], magic1: &[u8; MAGIC_N], off: &mut usize) -> bool {
    if let Some(next) = find_bytes(data, magic1, (*off).saturating_add(1)) {
        *off = next;
        return true;
    }
    let keep = suffix_prefix_len(data, magic1);
    *off = data.len() - keep;
    false
}
fn read_u16(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}
fn read_u32(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}
fn parse_buffered<F>(
    conn: &Arc<Connection>,
    input: &mut InputBuffer,
    magic1: &[u8; MAGIC_N],
    magic2: &[u8; MAGIC_N],
    mut deliver: F,
) -> bool
where
    F: FnMut(bool, Eid, Vec<u8>, Lease) -> bool,
{
    let mut progressed = false;
    let mut off = 0usize;
    let mut frames = 0usize;
    let mut parse_steps = 0usize;
    while !conn.closed.load(Ordering::Acquire)
        && frames < MAX_PARSE_FRAMES_PER_CALL
        && parse_steps < MAX_PARSE_STEPS_PER_CALL
    {
        parse_steps += 1;
        if off >= input.data.len() || !conn.has_recv_room() {
            break;
        }
        let Some(start) = find_bytes(&input.data, magic1, off) else {
            let remaining = &input.data[off..];
            let keep = suffix_prefix_len(remaining, magic1);
            let new_off = input.data.len() - keep;
            if new_off > off {
                progressed = true;
            }
            off = new_off;
            break;
        };
        if start > off {
            off = start;
            progressed = true;
        }
        let authed = conn.authed.load(Ordering::Acquire);
        let header_size = if authed { AUTH_HEAD + EID_N } else { UNAUTH_HEAD };
        let body_size = MAGIC_N + header_size;
        if input.data.len() - off < body_size {
            break;
        }
        let base = &input.data[off..];
        let payload_size = if authed {
            read_u32(&base[MAGIC_N..MAGIC_N + 4]) as usize
        } else {
            read_u16(&base[MAGIC_N..MAGIC_N + 2]) as usize
        };
        let mut eid = [0u8; EID_N];
        if authed {
            let flag = base[MAGIC_N + 4];
            if flag != b'0' && flag != b'1' {
                progressed = true;
                if !resync_after_malformed(&input.data, magic1, &mut off) {
                    break;
                }
                continue;
            }
            eid.copy_from_slice(&base[MAGIC_N + AUTH_HEAD..MAGIC_N + AUTH_HEAD + EID_N]);
        }
        let max_payload = if authed { MAX_AUTH_PAYLOAD } else { MAX_UNAUTH_PAYLOAD };
        if payload_size > max_payload {
            progressed = true;
            if !resync_after_malformed(&input.data, magic1, &mut off) {
                break;
            }
            continue;
        }
        let total_size = body_size + payload_size + MAGIC_N;
        if input.data.len() - off < total_size {
            break;
        }
        let trailer_start = off + total_size - MAGIC_N;
        if input.data[trailer_start..trailer_start + MAGIC_N] != magic2[..] {
            if let Some(nested) = find_bytes(&input.data, magic1, off + MAGIC_N) {
                if nested < off + total_size {
                    off = nested;
                } else {
                    off += total_size;
                }
            } else {
                off += total_size;
            }
            frames += 1;
            progressed = true;
            continue;
        }
        let accounting = payload_size + std::mem::size_of::<Message>() + 32;
        let Some(memory) = Lease::new(&conn.input_global, &conn.local_memory, accounting) else {
            off += total_size;
            frames += 1;
            progressed = true;
            continue;
        };
        let payload_start = off + body_size;
        let mut payload = Vec::new();
        if payload.try_reserve_exact(payload_size).is_err() {
            off += total_size;
            frames += 1;
            progressed = true;
            continue;
        }
        payload.extend_from_slice(&input.data[payload_start..payload_start + payload_size]);
        if !deliver(authed, eid, payload, memory) {
            input.compact(conn, off);
            return progressed;
        }
        off += total_size;
        frames += 1;
        progressed = true;
    }
    input.compact(conn, off);
    progressed
}
fn make_frame(
    magic1: &[u8; MAGIC_N],
    magic2: &[u8; MAGIC_N],
    pending: &Pending,
) -> Option<Vec<u8>> {
    let payload_size = pending.payload.len();
    let header_size = if pending.authed {
        AUTH_HEAD + EID_N
    } else {
        UNAUTH_HEAD
    };
    let total = MAGIC_N + header_size + payload_size + MAGIC_N;
    let mut out = Vec::new();
    out.try_reserve_exact(total).ok()?;
    out.extend_from_slice(magic1);
    if pending.authed {
        out.extend_from_slice(&(payload_size as u32).to_be_bytes());
        out.push(b'0');
        out.extend_from_slice(&pending.eid);
    } else {
        out.extend_from_slice(&(payload_size as u16).to_be_bytes());
    }
    out.extend_from_slice(&pending.payload);
    out.extend_from_slice(magic2);
    Some(out)
}
fn cleanup_exchanges(conn: &Connection) {
    let now = Instant::now();
    {
        let mut last = mutex_lock(&conn.last_cleanup);
        if now.saturating_duration_since(*last) < CLEANUP_INTERVAL {
            return;
        }
        *last = now;
    }
    let mut changed = false;
    {
        let mut state = mutex_lock(&conn.state);
        let old_len = state.eid_activity.len();
        state
            .eid_activity
            .retain(|_, last_seen| now.saturating_duration_since(*last_seen) < EID_TTL);
        if old_len != state.eid_activity.len() {
            changed = true;
            let active_eids: HashSet<Eid> = state.eid_activity.keys().copied().collect();
            state.recvq.retain(|message| {
                !message.authed || active_eids.contains(&message.eid)
            });
            state.sendq.retain(|pending| {
                !pending.authed || active_eids.contains(&pending.eid)
            });
        }
    }
    if changed {
        conn.recv_notify.notify_waiters();
        conn.send_notify.notify_one();
    }
}
async fn read_loop<R>(
    conn: Arc<Connection>,
    mut reader: R,
    magic1: [u8; MAGIC_N],
    magic2: [u8; MAGIC_N],
    deliver: DeliverFn,
) where
    R: AsyncRead + Unpin,
{
    let mut input = InputBuffer::new();
    let mut buffer = [0u8; READ_CHUNK];
    let mut total_read = 0usize;
    let mut cleanup = tokio::time::interval(CLEANUP_INTERVAL);
    cleanup.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        if conn.closed.load(Ordering::Acquire) {
            return;
        }
        if !conn.authed.load(Ordering::Acquire) && conn.connect_time.elapsed() >= UNAUTH_TIMEOUT {
            conn.close();
            return;
        }
        if !input.data.is_empty() && conn.has_recv_room() {
            let target_conn = Arc::clone(&conn);
            let progressed = parse_buffered(&conn, &mut input, &magic1, &magic2, |authed, eid, payload, memory| {
                deliver(Arc::clone(&target_conn), authed, eid, payload, memory)
            });
            if progressed && !input.data.is_empty() && conn.has_recv_room() {
                tokio::task::yield_now().await;
                continue;
            }
        }
        if conn.closed.load(Ordering::Acquire) {
            return;
        }
        let is_backpressured = conn.backpressure.load(Ordering::Acquire);
        let receive_queue_full = !conn.has_recv_room();
        if is_backpressured || receive_queue_full {
            tokio::select! {
                _ = conn.cancel.cancelled() => return,
                _ = conn.io_notify.notified() => continue,
                _ = conn.room_notify.notified() => continue,
                _ = cleanup.tick() => cleanup_exchanges(&conn),
            }
            continue;
        }
        let remaining = UNAUTH_TIMEOUT.saturating_sub(conn.connect_time.elapsed());
        let is_authed = conn.authed.load(Ordering::Acquire);
        let read_result = tokio::select! {
            _ = conn.cancel.cancelled() => return,
            _ = conn.io_notify.notified() => continue,
            _ = conn.room_notify.notified() => continue,
            _ = cleanup.tick() => {
                cleanup_exchanges(&conn);
                continue;
            },
            result = async {
                if is_authed {
                    reader.read(&mut buffer).await
                } else {
                    match timeout(remaining, reader.read(&mut buffer)).await {
                        Ok(result) => result,
                        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "unauthenticated connection timed out")),
                    }
                }
            } => result,
        };
        match read_result {
            Ok(0) => {
                conn.close();
                return;
            }
            Ok(got) => {
                total_read += got;
                if got > MAX_INPUT_BUFFER.saturating_sub(input.data.len())
                    || !input.ensure_capacity(&conn, input.data.len() + got)
                {
                    conn.close();
                    return;
                }
                input.data.extend_from_slice(&buffer[..got]);
                let target_conn = Arc::clone(&conn);
                let progressed = parse_buffered(&conn, &mut input, &magic1, &magic2, |authed, eid, payload, memory| {
                    deliver(Arc::clone(&target_conn), authed, eid, payload, memory)
                });
                if conn.closed.load(Ordering::Acquire) {
                    return;
                }
                if progressed && !input.data.is_empty() && conn.has_recv_room() {
                    tokio::task::yield_now().await;
                    continue;
                }
                if total_read >= MAX_READ_PER_TICK {
                    total_read = 0;
                    tokio::task::yield_now().await;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(_) => {
                conn.close();
                return;
            }
        }
    }
}
async fn write_loop<W>(
    conn: Arc<Connection>,
    mut writer: W,
    magic1: [u8; MAGIC_N],
    magic2: [u8; MAGIC_N],
) where
    W: AsyncWrite + Unpin,
{
    loop {
        let notified = conn.send_notify.notified();
        let pending = {
            let mut state = mutex_lock(&conn.state);
            state.sendq.pop_front()
        };
        let Some(pending) = pending else {
            if conn.closed.load(Ordering::Acquire) {
                return;
            }
            tokio::select! {
                _ = conn.cancel.cancelled() => return,
                _ = notified => continue,
            }
        };
        let frame_size = MAGIC_N
            + if pending.authed { AUTH_HEAD + EID_N } else { UNAUTH_HEAD }
            + pending.payload.len()
            + MAGIC_N;
        let Some(_wire_memory) = Lease::new(&conn.input_global, &conn.local_memory, frame_size) else {
            conn.close();
            return;
        };
        let Some(wire) = make_frame(&magic1, &magic2, &pending) else {
            conn.close();
            return;
        };
        for chunk in wire.chunks(MAX_WRITE_PER_TICK) {
            let write_result = tokio::select! {
                _ = conn.cancel.cancelled() => return,
                result = writer.write_all(chunk) => result,
            };
            if write_result.is_err() {
                conn.close();
                return;
            }
            tokio::task::yield_now().await;
        }
    }
}
async fn run_connection(
    stream: TcpStream,
    conn: Arc<Connection>,
    magic1: [u8; MAGIC_N],
    magic2: [u8; MAGIC_N],
    deliver: DeliverFn,
) {
    let (reader, writer) = stream.into_split();
    tokio::select! {
        _ = read_loop(Arc::clone(&conn), reader, magic1, magic2, deliver) => {},
        _ = write_loop(Arc::clone(&conn), writer, magic1, magic2) => {},
        _ = conn.cancel.cancelled() => {},
    }
    conn.close();
}
fn validate_timeout(timeout_duration: Option<Duration>) -> Result<Option<Duration>> {
    const MAX_TIMEOUT: Duration = Duration::from_secs(365 * 24 * 60 * 60);
    if timeout_duration.map(|duration| duration > MAX_TIMEOUT).unwrap_or(false) {
        return Err(BackendError::InvalidArgument(
            "timeout must be between 0 and 365 days, or None".into(),
        ));
    }
    Ok(timeout_duration)
}
async fn pop_message(
    conn: &Arc<Connection>,
    eid: Option<Eid>,
    want_authed: bool,
    timeout_duration: Option<Duration>,
) -> Option<Vec<u8>> {
    let deadline = timeout_duration.map(|duration| TokioInstant::now() + duration);
    loop {
        let notified = conn.recv_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        {
            let mut state = mutex_lock(&conn.state);
            if let Some(index) = state.recvq.iter().position(|message| {
                message.authed == want_authed && (!want_authed || Some(message.eid) == eid)
            }) {
                let message = state.recvq.remove(index).expect("message index was found");
                drop(state);
                conn.room_notify.notify_one();
                return Some(message.payload);
            }
            if conn.closed.load(Ordering::Acquire)
                || conn.authed.load(Ordering::Acquire) != want_authed
            {
                return None;
            }
        }
        if let Some(deadline) = deadline {
            tokio::select! {
                _ = conn.cancel.cancelled() => return None,
                _ = &mut notified => {},
                _ = sleep_until(deadline) => return None,
            }
        } else {
            tokio::select! {
                _ = conn.cancel.cancelled() => return None,
                _ = &mut notified => {},
            }
        }
    }
}
fn validate_pool_size(workers: usize) -> Result<usize> {
    if workers == 0 {
        return Err(BackendError::InvalidArgument(
            "concurrency limit must be >= 1".into(),
        ));
    }
    if workers > MAX_POOL_WORKERS {
        return Err(BackendError::InvalidArgument(
            "concurrency limit must be <= 64".into(),
        ));
    }
    let scaled = workers.saturating_mul(64);
    Ok(if scaled > MAX_PENDING_CALLBACKS_MAX {
        MAX_PENDING_CALLBACKS_MAX
    } else {
        MAX_PENDING_CALLBACKS_MIN.max(scaled)
    })
}
struct CallbackPool {
    sender: Sender<Job>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}
impl CallbackPool {
    fn new(workers: usize) -> Result<Arc<Self>> {
        let pending_limit = validate_pool_size(workers)?;
        Self::new_with_limit(workers, pending_limit)
    }
    fn new_with_limit(workers: usize, pending_limit: usize) -> Result<Arc<Self>> {
        validate_pool_size(workers)?;
        let (sender, receiver) = async_channel::bounded::<Job>(pending_limit);
        let mut worker_tasks = Vec::with_capacity(workers);
        for _ in 0..workers {
            let receiver = receiver.clone();
            worker_tasks.push(tokio::spawn(callback_worker(receiver)));
        }
        Ok(Arc::new(Self {
            sender,
            workers: Mutex::new(worker_tasks),
        }))
    }
    fn submit(&self, job: Job) -> bool {
        match self.sender.try_send(job) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => false,
        }
    }
    fn close(&self) {
        self.sender.close();
    }
    async fn close_and_wait(&self) {
        self.sender.close();
        let workers = {
            let mut tasks = mutex_lock(&self.workers);
            std::mem::take(&mut *tasks)
        };
        for worker in workers {
            let _ = worker.await;
        }
    }
}
async fn callback_worker(receiver: Receiver<Job>) {
    while let Ok(job) = receiver.recv().await {
        let future = job();
        if tokio::spawn(future).await.is_err() {
            log_callback_error("callback", "callback panicked or callback task failed");
        }
    }
}
fn log_callback_error(where_: &str, what: &str) {
    static LAST_LOG: Mutex<Option<Instant>> = Mutex::new(None);
    let now = Instant::now();
    let mut last = mutex_lock(&LAST_LOG);
    if last
        .as_ref()
        .map(|previous| now.saturating_duration_since(*previous) >= Duration::from_secs(5))
        .unwrap_or(true)
    {
        *last = Some(now);
        eprintln!("[{where_}] callback error: {what}");
    }
}
pub type HandshakeCallback = Arc<dyn Fn(Vec<u8>) -> BoxFuture<'static, ()> + Send + Sync + 'static>;
pub type ServerExchangeCallback = Arc<dyn Fn(Vec<u8>, Vec<u8>) -> BoxFuture<'static, ()> + Send + Sync + 'static>;
pub type ClientExchangeCallback = Arc<dyn Fn(Vec<u8>) -> BoxFuture<'static, ()> + Send + Sync + 'static>;
pub type DisconnectCallback = Arc<dyn Fn(Vec<u8>) -> BoxFuture<'static, ()> + Send + Sync + 'static>;
#[derive(Clone, Default)]
pub struct ServerCallbacks {
    pub handshake_worker: Option<HandshakeCallback>,
    pub on_exchange: Option<ServerExchangeCallback>,
    pub on_disconnect: Option<DisconnectCallback>,
}
#[derive(Clone, Default)]
pub struct ClientCallbacks {
    pub on_exchange: Option<ClientExchangeCallback>,
}
#[derive(Default)]
struct Registry {
    ids: HashMap<Vec<u8>, Arc<Connection>>,
    temporary_ids: HashMap<Vec<u8>, Arc<Connection>>,
}
#[derive(Default)]
struct PeerLimits {
    counts: HashMap<IpAddr, usize>,
    accepts: HashMap<IpAddr, VecDeque<Instant>>,
    last_cleanup: Option<Instant>,
}
impl PeerLimits {
    fn prune(&mut self, now: Instant, force: bool) {
        if !force
            && self
                .last_cleanup
                .map(|last| now.saturating_duration_since(last) < Duration::from_secs(10))
                .unwrap_or(false)
            && self.accepts.len() < MAX_PEER_BUCKETS
        {
            return;
        }
        self.last_cleanup = Some(now);
        let active_peers: HashSet<IpAddr> = self.counts.keys().copied().collect();
        self.accepts.retain(|peer, times| {
            while times
                .front()
                .map(|time| now.saturating_duration_since(*time) >= Duration::from_secs(60))
                .unwrap_or(false)
            {
                times.pop_front();
            }
            !times.is_empty() || active_peers.contains(peer)
        });
    }
    fn allow(&mut self, peer: IpAddr) -> bool {
        let now = Instant::now();
        self.prune(now, false);
        if self.counts.get(&peer).copied().unwrap_or(0) >= MAX_CONNECTIONS_PER_PEER {
            return false;
        }
        if !self.accepts.contains_key(&peer) && self.accepts.len() >= MAX_PEER_BUCKETS {
            self.prune(now, true);
            if self.accepts.len() >= MAX_PEER_BUCKETS {
                return false;
            }
        }
        let times = self.accepts.entry(peer).or_default();
        while times
            .front()
            .map(|time| now.saturating_duration_since(*time) >= Duration::from_secs(60))
            .unwrap_or(false)
        {
            times.pop_front();
        }
        if times.len() >= MAX_NEW_CONNECTIONS_PER_PEER_PER_MINUTE {
            return false;
        }
        times.push_back(now);
        true
    }
    fn add_connection(&mut self, peer: IpAddr) {
        *self.counts.entry(peer).or_insert(0) += 1;
    }
    fn remove_connection(&mut self, peer: IpAddr) {
        let should_remove = match self.counts.get_mut(&peer) {
            Some(count) if *count > 1 => {
                *count -= 1;
                false
            }
            Some(_) => true,
            None => false,
        };
        if should_remove {
            self.counts.remove(&peer);
        }
    }
}
struct ServerInner {
    host: String,
    port: u16,
    magic1: [u8; MAGIC_N],
    magic2: [u8; MAGIC_N],
    callbacks: ServerCallbacks,
    simultaneous_handshakes: usize,
    simultaneous_exchanges: usize,
    global_memory: Arc<Quota>,
    registry: Mutex<Registry>,
    connections: Mutex<HashMap<u64, Arc<Connection>>>,
    peer_limits: Mutex<PeerLimits>,
    next_connection_id: AtomicU64,
    running: AtomicBool,
    stopping: AtomicBool,
    lifecycle: tokio::sync::Mutex<()>,
    accept_task: Mutex<Option<JoinHandle<()>>>,
    handshake_pool: Mutex<Option<Arc<CallbackPool>>>,
    exchange_pool: Mutex<Option<Arc<CallbackPool>>>,
    disconnect_pool: Mutex<Option<Arc<CallbackPool>>>,
}
impl ServerInner {
    fn find(&self, id: &[u8]) -> Option<Arc<Connection>> {
        mutex_lock(&self.registry).ids.get(id).cloned()
    }
    fn find_temp(&self, id: &[u8]) -> Option<Arc<Connection>> {
        mutex_lock(&self.registry).temporary_ids.get(id).cloned()
    }
    fn deliver_message(
        self: &Arc<Self>,
        conn: Arc<Connection>,
        authed: bool,
        eid: Eid,
        payload: Vec<u8>,
        memory: Lease,
    ) -> bool {
        let mut fresh_eid = false;
        let mut exceeded = false;
        {
            let mut state = mutex_lock(&conn.state);
            if conn.closed.load(Ordering::Acquire) || state.recvq.len() >= QUEUE_LIMIT {
                return false;
            }
            if authed {
                let now = Instant::now();
                if let Some(last) = state.eid_activity.get_mut(&eid) {
                    *last = now;
                } else {
                    state
                        .eid_activity
                        .retain(|_, last| now.saturating_duration_since(*last) < EID_TTL);
                    if state.eid_activity.len() >= MAX_ACTIVE_EIDS_PER_CONNECTION {
                        exceeded = true;
                    } else {
                        state.eid_activity.insert(eid, now);
                        fresh_eid = true;
                    }
                }
            }
            if !exceeded {
                state.recvq.push_back(Message {
                    eid,
                    payload,
                    authed,
                    _memory: memory,
                });
            }
        }
        if exceeded {
            conn.close();
            return false;
        }
        conn.recv_notify.notify_waiters();
        if !authed && conn.server_side && !conn.handshake_started.swap(true, Ordering::AcqRel) {
            if let (Some(callback), Some(pool)) = (
                self.callbacks.handshake_worker.clone(),
                mutex_lock(&self.handshake_pool).clone(),
            ) {
                let temp = conn.temp_cid.clone();
                let weak_inner = Arc::downgrade(self);
                let connection_id = conn.connection_id;
                let job: Job = Box::new(move || {
                    Box::pin(async move {
                        let Some(inner) = weak_inner.upgrade() else { return };
                        let Some(current) = inner.find_temp(&temp) else { return };
                        if current.closed.load(Ordering::Acquire)
                            || current.connection_id != connection_id
                        {
                            return;
                        }
                        callback(temp).await;
                    })
                });
                if !pool.submit(job) {
                    log_callback_error("handshake_worker", "callback queue is full or stopped");
                }
            }
        } else if authed && fresh_eid {
            if let (Some(callback), Some(pool)) = (
                self.callbacks.on_exchange.clone(),
                mutex_lock(&self.exchange_pool).clone(),
            ) {
                let id = read_lock(&conn.cid).clone();
                let eid_vec = eid.to_vec();
                let weak_inner = Arc::downgrade(self);
                let weak_conn = Arc::downgrade(&conn);
                let connection_id = conn.connection_id;
                let job: Job = Box::new(move || {
                    Box::pin(async move {
                        let (Some(inner), Some(current)) = (weak_inner.upgrade(), weak_conn.upgrade()) else {
                            return;
                        };
                        if current.closed.load(Ordering::Acquire)
                            || current.connection_id != connection_id
                            || !inner
                                .find(&id)
                                .map(|found| Arc::ptr_eq(&found, &current))
                                .unwrap_or(false)
                        {
                            return;
                        }
                        if !mutex_lock(&current.state).eid_activity.contains_key(&eid) {
                            return;
                        }
                        callback(id, eid_vec).await;
                    })
                });
                if !pool.submit(job) {
                    log_callback_error("on_exchange", "callback queue is full or stopped");
                }
            }
        }
        true
    }
    fn queue_disconnect(&self, conn: &Arc<Connection>) {
        if self.callbacks.on_disconnect.is_none()
            || !conn.authed.load(Ordering::Acquire)
            || read_lock(&conn.cid).is_empty()
            || conn.disconnect_notified.swap(true, Ordering::AcqRel)
        {
            return;
        }
        let Some(pool) = mutex_lock(&self.disconnect_pool).clone() else {
            return;
        };
        let callback = self.callbacks.on_disconnect.as_ref().expect("checked above").clone();
        let id = read_lock(&conn.cid).clone();
        if !pool.submit(Box::new(move || Box::pin(async move { callback(id).await }))) {
            log_callback_error("on_disconnect", "callback queue is full or stopped");
        }
    }
    fn cleanup_connection(self: &Arc<Self>, conn: &Arc<Connection>) {
        self.queue_disconnect(conn);
        {
            let mut connections = mutex_lock(&self.connections);
            connections.remove(&conn.connection_id);
        }
        {
            let mut registry = mutex_lock(&self.registry);
            registry.ids.retain(|_, current| !Arc::ptr_eq(current, conn));
            registry
                .temporary_ids
                .retain(|_, current| !Arc::ptr_eq(current, conn));
        }
        if let Some(peer) = conn.peer {
            mutex_lock(&self.peer_limits).remove_connection(peer);
        }
        conn.close();
    }
}
#[derive(Clone)]
pub struct Server {
    inner: Arc<ServerInner>,
    lifetime: Arc<()>,
}
impl Server {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        callbacks: ServerCallbacks,
        simultaneous_handshakes: usize,
        simultaneous_exchanges: usize,
    ) -> Result<Self> {
        validate_pool_size(simultaneous_handshakes)?;
        validate_pool_size(simultaneous_exchanges)?;
        let magic1 = random_array::<MAGIC_N>()?;
        let mut magic2 = random_array::<MAGIC_N>()?;
        while magic1 == magic2 {
            magic2 = random_array::<MAGIC_N>()?;
        }
        Ok(Self {
            lifetime: Arc::new(()),
            inner: Arc::new(ServerInner {
                host: host.into(),
                port,
                magic1,
                magic2,
                callbacks,
                simultaneous_handshakes,
                simultaneous_exchanges,
                global_memory: Quota::new(MAX_GLOBAL_BUFFERED_BYTES),
                registry: Mutex::new(Registry::default()),
                connections: Mutex::new(HashMap::new()),
                peer_limits: Mutex::new(PeerLimits::default()),
                next_connection_id: AtomicU64::new(1),
                running: AtomicBool::new(false),
                stopping: AtomicBool::new(false),
                lifecycle: tokio::sync::Mutex::new(()),
                accept_task: Mutex::new(None),
                handshake_pool: Mutex::new(None),
                exchange_pool: Mutex::new(None),
                disconnect_pool: Mutex::new(None),
            }),
        })
    }
    pub fn handle(&self) -> ServerHandle {
        ServerHandle {
            inner: Arc::downgrade(&self.inner),
        }
    }
    pub async fn start(&self) -> Result<()> {
        let _lifecycle = self.inner.lifecycle.lock().await;
        if self.inner.stopping.load(Ordering::Acquire) {
            return Err(BackendError::Stopped);
        }
        if self.inner.running.swap(true, Ordering::AcqRel) {
            return Err(BackendError::AlreadyRunning);
        }
        let addresses: Vec<std::net::SocketAddr> = if self.inner.host.is_empty() {
            vec![
                std::net::SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                    self.inner.port,
                ),
                std::net::SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    self.inner.port,
                ),
            ]
        } else {
            match lookup_host((self.inner.host.as_str(), self.inner.port)).await {
                Ok(addresses) => addresses.collect(),
                Err(error) => {
                    self.inner.running.store(false, Ordering::Release);
                    return Err(error.into());
                }
            }
        };
        let mut listener = None;
        let mut last_bind_error = None;
        for address in addresses {
            match bind_listener(address) {
                Ok(bound) => {
                    listener = Some(bound);
                    break;
                }
                Err(error) => last_bind_error = Some(error),
            }
        }
        let Some(listener) = listener else {
            self.inner.running.store(false, Ordering::Release);
            return Err(last_bind_error
                .map(BackendError::Io)
                .unwrap_or_else(|| BackendError::InvalidArgument("no bind address resolved".into())));
        };
        let pools_result = (|| -> Result<_> {
            let handshake_pool = if self.inner.callbacks.handshake_worker.is_some() {
                Some(CallbackPool::new(self.inner.simultaneous_handshakes)?)
            } else {
                None
            };
            let exchange_pool = if self.inner.callbacks.on_exchange.is_some() {
                Some(CallbackPool::new(self.inner.simultaneous_exchanges)?)
            } else {
                None
            };
            let disconnect_pool = if self.inner.callbacks.on_disconnect.is_some() {
                Some(CallbackPool::new_with_limit(1, MAX_PENDING_CALLBACKS_MAX)?)
            } else {
                None
            };
            Ok((handshake_pool, exchange_pool, disconnect_pool))
        })();
        let (handshake_pool, exchange_pool, disconnect_pool) = match pools_result {
            Ok(pools) => pools,
            Err(error) => {
                self.inner.running.store(false, Ordering::Release);
                return Err(error);
            }
        };
        *mutex_lock(&self.inner.handshake_pool) = handshake_pool;
        *mutex_lock(&self.inner.exchange_pool) = exchange_pool;
        *mutex_lock(&self.inner.disconnect_pool) = disconnect_pool;
        let inner = Arc::clone(&self.inner);
        let task = tokio::spawn(async move {
            accept_loop(inner, listener).await;
        });
        *mutex_lock(&self.inner.accept_task) = Some(task);
        Ok(())
    }
    pub async fn stop(&self) {
        let _lifecycle = self.inner.lifecycle.lock().await;
        if self.inner.stopping.swap(true, Ordering::AcqRel) {
            return;
        }
        self.inner.running.store(false, Ordering::Release);
        let accept_task = { mutex_lock(&self.inner.accept_task).take() };
        if let Some(task) = accept_task {
            task.abort();
            let _ = task.await;
        }
        let remaining: Vec<Arc<Connection>> =
            mutex_lock(&self.inner.connections).values().cloned().collect();
        for conn in &remaining {
            self.inner.queue_disconnect(conn);
            conn.close();
        }
        {
            let mut registry = mutex_lock(&self.inner.registry);
            registry.ids.clear();
            registry.temporary_ids.clear();
        }
        mutex_lock(&self.inner.connections).clear();
        *mutex_lock(&self.inner.peer_limits) = PeerLimits::default();
        let handshake_pool = { mutex_lock(&self.inner.handshake_pool).take() };
        let exchange_pool = { mutex_lock(&self.inner.exchange_pool).take() };
        let disconnect_pool = { mutex_lock(&self.inner.disconnect_pool).take() };
        if let Some(pool) = handshake_pool {
            pool.close_and_wait().await;
        }
        if let Some(pool) = exchange_pool {
            pool.close_and_wait().await;
        }
        if let Some(pool) = disconnect_pool {
            pool.close_and_wait().await;
        }
    }
    pub fn magic1(&self) -> [u8; MAGIC_N] {
        self.inner.magic1
    }
    pub fn magic2(&self) -> [u8; MAGIC_N] {
        self.inner.magic2
    }
    pub fn is_authed(&self, cid: &[u8]) -> bool {
        self.inner
            .find(cid)
            .map(|conn| conn.authed.load(Ordering::Acquire))
            .unwrap_or(false)
    }
    pub fn set_backpressure(&self, cid: &[u8], value: bool) -> Result<()> {
        let conn = self.inner.find(cid).ok_or(BackendError::UnknownCid)?;
        conn.backpressure.store(value, Ordering::Release);
        conn.io_notify.notify_one();
        Ok(())
    }
    pub fn close_client(&self, cid: &[u8]) -> Result<()> {
        let conn = {
            let mut registry = mutex_lock(&self.inner.registry);
            let conn = registry.ids.remove(cid).ok_or(BackendError::UnknownCid)?;
            conn
        };
        conn.close();
        Ok(())
    }
    pub fn send(&self, data: Vec<u8>, cid: &[u8], requested_eid: Option<Eid>) -> Result<Eid> {
        let conn = self.inner.find(cid).ok_or(BackendError::UnknownCid)?;
        if !conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::NotAuthenticated);
        }
        let eid = choose_eid(&conn, requested_eid)?;
        conn.queue_pending(data, eid, true)?;
        Ok(eid)
    }
    pub fn send_handshake(&self, temp_cid: &[u8], data: Vec<u8>) -> Result<()> {
        let conn = self
            .inner
            .find_temp(temp_cid)
            .ok_or(BackendError::UnknownTempCid)?;
        if conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::AlreadyAuthenticated);
        }
        conn.queue_pending(data, [0u8; EID_N], false)
    }
    pub async fn recv(
        &self,
        cid: &[u8],
        eid: Eid,
        timeout_duration: Option<Duration>,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.inner.find(cid).ok_or(BackendError::UnknownCid)?;
        if !conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::NotAuthenticated);
        }
        let timeout_duration = validate_timeout(timeout_duration)?;
        Ok(pop_message(&conn, Some(eid), true, timeout_duration).await)
    }
    pub async fn recv_handshake(
        &self,
        temp_cid: &[u8],
        timeout_duration: Option<Duration>,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self
            .inner
            .find_temp(temp_cid)
            .ok_or(BackendError::UnknownTempCid)?;
        if conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::AlreadyAuthenticated);
        }
        let timeout_duration = validate_timeout(timeout_duration)?;
        Ok(pop_message(&conn, None, false, timeout_duration).await)
    }
    pub fn auth_finished(
        &self,
        temp_cid: &[u8],
        new_cid: Vec<u8>,
        confirmation_payload: Option<Vec<u8>>,
    ) -> Result<bool> {
        if new_cid.is_empty() {
            return Err(BackendError::InvalidArgument(
                "new_cid must not be empty".into(),
            ));
        }
        if new_cid.len() > MAX_CID_BYTES {
            return Err(BackendError::InvalidArgument(
                "new_cid exceeds the 256-byte limit".into(),
            ));
        }
        let mut registry = mutex_lock(&self.inner.registry);
        let conn = registry
            .temporary_ids
            .get(temp_cid)
            .cloned()
            .ok_or(BackendError::UnknownTempCid)?;
        if conn.closed.load(Ordering::Acquire) {
            return Err(BackendError::ConnectionClosed);
        }
        if registry.ids.contains_key(&new_cid) {
            return Err(BackendError::InvalidArgument(
                "new_cid already in use".into(),
            ));
        }
        if let Some(payload) = confirmation_payload {
            conn.queue_pending(payload, [0u8; EID_N], false)?;
        }
        *write_lock(&conn.cid) = new_cid.clone();
        registry.ids.insert(new_cid, Arc::clone(&conn));
        registry.temporary_ids.remove(temp_cid);
        conn.authed.store(true, Ordering::Release);
        conn.recv_notify.notify_waiters();
        conn.io_notify.notify_one();
        Ok(true)
    }
}
#[derive(Clone)]
pub struct ServerHandle {
    inner: std::sync::Weak<ServerInner>,
}
impl ServerHandle {
    fn upgrade(&self) -> Result<Arc<ServerInner>> {
        let inner = self.inner.upgrade().ok_or(BackendError::Stopped)?;
        if inner.stopping.load(Ordering::Acquire) {
            return Err(BackendError::Stopped);
        }
        Ok(inner)
    }
    pub fn magic1(&self) -> Result<[u8; MAGIC_N]> {
        Ok(self.upgrade()?.magic1)
    }
    pub fn magic2(&self) -> Result<[u8; MAGIC_N]> {
        Ok(self.upgrade()?.magic2)
    }
    pub fn is_authed(&self, cid: &[u8]) -> Result<bool> {
        let inner = self.upgrade()?;
        Ok(inner
            .find(cid)
            .map(|conn| conn.authed.load(Ordering::Acquire))
            .unwrap_or(false))
    }
    pub fn set_backpressure(&self, cid: &[u8], value: bool) -> Result<()> {
        let inner = self.upgrade()?;
        let conn = inner.find(cid).ok_or(BackendError::UnknownCid)?;
        conn.backpressure.store(value, Ordering::Release);
        conn.io_notify.notify_one();
        Ok(())
    }
    pub fn close_client(&self, cid: &[u8]) -> Result<()> {
        let inner = self.upgrade()?;
        let conn = {
            let mut registry = mutex_lock(&inner.registry);
            registry.ids.remove(cid).ok_or(BackendError::UnknownCid)?
        };
        conn.close();
        Ok(())
    }
    pub fn send(&self, data: Vec<u8>, cid: &[u8], requested_eid: Option<Eid>) -> Result<Eid> {
        let inner = self.upgrade()?;
        let conn = inner.find(cid).ok_or(BackendError::UnknownCid)?;
        if !conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::NotAuthenticated);
        }
        let eid = choose_eid(&conn, requested_eid)?;
        conn.queue_pending(data, eid, true)?;
        Ok(eid)
    }
    pub fn send_handshake(&self, temp_cid: &[u8], data: Vec<u8>) -> Result<()> {
        let inner = self.upgrade()?;
        let conn = inner
            .find_temp(temp_cid)
            .ok_or(BackendError::UnknownTempCid)?;
        if conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::AlreadyAuthenticated);
        }
        conn.queue_pending(data, [0u8; EID_N], false)
    }
    pub async fn recv(
        &self,
        cid: &[u8],
        eid: Eid,
        timeout_duration: Option<Duration>,
    ) -> Result<Option<Vec<u8>>> {
        let inner = self.upgrade()?;
        let conn = inner.find(cid).ok_or(BackendError::UnknownCid)?;
        if !conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::NotAuthenticated);
        }
        let timeout_duration = validate_timeout(timeout_duration)?;
        Ok(pop_message(&conn, Some(eid), true, timeout_duration).await)
    }
    pub async fn recv_handshake(
        &self,
        temp_cid: &[u8],
        timeout_duration: Option<Duration>,
    ) -> Result<Option<Vec<u8>>> {
        let inner = self.upgrade()?;
        let conn = inner
            .find_temp(temp_cid)
            .ok_or(BackendError::UnknownTempCid)?;
        if conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::AlreadyAuthenticated);
        }
        let timeout_duration = validate_timeout(timeout_duration)?;
        Ok(pop_message(&conn, None, false, timeout_duration).await)
    }
    pub fn auth_finished(
        &self,
        temp_cid: &[u8],
        new_cid: Vec<u8>,
        confirmation_payload: Option<Vec<u8>>,
    ) -> Result<bool> {
        let inner = self.upgrade()?;
        if new_cid.is_empty() {
            return Err(BackendError::InvalidArgument(
                "new_cid must not be empty".into(),
            ));
        }
        if new_cid.len() > MAX_CID_BYTES {
            return Err(BackendError::InvalidArgument(
                "new_cid exceeds the 256-byte limit".into(),
            ));
        }
        let mut registry = mutex_lock(&inner.registry);
        let conn = registry
            .temporary_ids
            .get(temp_cid)
            .cloned()
            .ok_or(BackendError::UnknownTempCid)?;
        if conn.closed.load(Ordering::Acquire) {
            return Err(BackendError::ConnectionClosed);
        }
        if registry.ids.contains_key(&new_cid) {
            return Err(BackendError::InvalidArgument(
                "new_cid already in use".into(),
            ));
        }
        if let Some(payload) = confirmation_payload {
            conn.queue_pending(payload, [0u8; EID_N], false)?;
        }
        *write_lock(&conn.cid) = new_cid.clone();
        registry.ids.insert(new_cid, Arc::clone(&conn));
        registry.temporary_ids.remove(temp_cid);
        conn.authed.store(true, Ordering::Release);
        conn.recv_notify.notify_waiters();
        conn.io_notify.notify_one();
        Ok(true)
    }
}
fn choose_eid(conn: &Connection, requested: Option<Eid>) -> Result<Eid> {
    if let Some(eid) = requested {
        return match conn.touch_eid(eid) {
            EidTouch::Fresh | EidTouch::Existing => Ok(eid),
            EidTouch::Limit => Err(BackendError::EidLimit),
            EidTouch::Closed => Err(BackendError::ConnectionClosed),
        };
    }
    for _ in 0..16 {
        let eid = random_array::<EID_N>()?;
        match conn.touch_eid(eid) {
            EidTouch::Fresh => return Ok(eid),
            EidTouch::Existing => continue,
            EidTouch::Limit => return Err(BackendError::EidLimit),
            EidTouch::Closed => return Err(BackendError::ConnectionClosed),
        }
    }
    Err(BackendError::InvalidArgument(
        "could not generate a unique EID".into(),
    ))
}
async fn accept_loop(inner: Arc<ServerInner>, listener: TcpListener) {
    while inner.running.load(Ordering::Acquire) && !inner.stopping.load(Ordering::Acquire) {
        let mut accepted_this_tick = 0usize;
        while accepted_this_tick < MAX_ACCEPT_PER_TICK {
            let accepted = listener.accept().await;
            let (mut stream, address) = match accepted {
                Ok(pair) => pair,
                Err(error) => {
                    if error.kind() != io::ErrorKind::Interrupted {
                        log_callback_error("server_accept", &error.to_string());
                        sleep(Duration::from_millis(10)).await;
                    }
                    break;
                }
            };
            accepted_this_tick += 1;
            if !inner.running.load(Ordering::Acquire) {
                break;
            }
            let connection_count = mutex_lock(&inner.connections).len();
            let unauth_count = mutex_lock(&inner.registry).temporary_ids.len();
            let peer = address.ip();
            let peer_ok = mutex_lock(&inner.peer_limits).allow(peer);
            if connection_count >= MAX_CONNECTIONS
                || unauth_count >= MAX_UNAUTH_CONNECTIONS
                || !peer_ok
            {
                drop(stream);
                continue;
            }
            tune_socket(&stream);
            let mut greeting = [0u8; MAGIC_N * 2];
            greeting[..MAGIC_N].copy_from_slice(&inner.magic1);
            greeting[MAGIC_N..].copy_from_slice(&inner.magic2);
            if timeout(GREETING_TIMEOUT, stream.write_all(&greeting))
                .await
                .map(|result| result.is_err())
                .unwrap_or(true)
            {
                drop(stream);
                continue;
            }
            let connection_id = inner.next_connection_id.fetch_add(1, Ordering::Relaxed);
            let connection_result = (|| -> Result<Arc<Connection>> {
                let mut registry = mutex_lock(&inner.registry);
                loop {
                    let candidate = random_vec(EID_N)?;
                    if registry.temporary_ids.contains_key(&candidate)
                        || registry.ids.contains_key(&candidate)
                    {
                        continue;
                    }
                    let conn = Connection::new(
                        Arc::clone(&inner.global_memory),
                        true,
                        connection_id,
                        candidate.clone(),
                        Some(peer),
                    );
                    registry
                        .temporary_ids
                        .insert(candidate.clone(), Arc::clone(&conn));
                    return Ok(conn);
                }
            })();
            let conn = match connection_result {
                Ok(conn) => conn,
                Err(_) => {
                    drop(stream);
                    continue;
                }
            };
            mutex_lock(&inner.connections).insert(connection_id, Arc::clone(&conn));
            mutex_lock(&inner.peer_limits).add_connection(peer);
            let weak_inner = Arc::downgrade(&inner);
            let deliver: DeliverFn = Arc::new(move |conn, authed, eid, payload, memory| {
                weak_inner
                    .upgrade()
                    .map(|inner| inner.deliver_message(conn, authed, eid, payload, memory))
                    .unwrap_or(false)
            });
            let connection_inner = Arc::clone(&inner);
            tokio::spawn(async move {
                run_connection(
                    stream,
                    Arc::clone(&conn),
                    connection_inner.magic1,
                    connection_inner.magic2,
                    deliver,
                )
                .await;
                connection_inner.cleanup_connection(&conn);
            });
        }
        if accepted_this_tick >= MAX_ACCEPT_PER_TICK {
            tokio::task::yield_now().await;
        }
    }
}
struct ClientInner {
    callbacks: ClientCallbacks,
    exchange_pool: Option<Arc<CallbackPool>>,
    conn: Mutex<Option<Arc<Connection>>>,
    magic1: [u8; MAGIC_N],
    magic2: [u8; MAGIC_N],
    connected: AtomicBool,
    stopping: AtomicBool,
    io_task: Mutex<Option<JoinHandle<()>>>,
}
impl ClientInner {
    fn deliver_message(
        self: &Arc<Self>,
        conn: Arc<Connection>,
        authed: bool,
        eid: Eid,
        payload: Vec<u8>,
        memory: Lease,
    ) -> bool {
        let mut fresh_eid = false;
        let mut exceeded = false;
        {
            let mut state = mutex_lock(&conn.state);
            if conn.closed.load(Ordering::Acquire) || state.recvq.len() >= QUEUE_LIMIT {
                return false;
            }
            if authed {
                let now = Instant::now();
                if let Some(last) = state.eid_activity.get_mut(&eid) {
                    *last = now;
                } else {
                    state
                        .eid_activity
                        .retain(|_, last| now.saturating_duration_since(*last) < EID_TTL);
                    if state.eid_activity.len() >= MAX_ACTIVE_EIDS_PER_CONNECTION {
                        exceeded = true;
                    } else {
                        state.eid_activity.insert(eid, now);
                        fresh_eid = true;
                    }
                }
            }
            if !exceeded {
                state.recvq.push_back(Message {
                    eid,
                    payload,
                    authed,
                    _memory: memory,
                });
            }
        }
        if exceeded {
            conn.close();
            return false;
        }
        conn.recv_notify.notify_waiters();
        if authed && fresh_eid {
            if let (Some(callback), Some(pool)) = (
                self.callbacks.on_exchange.clone(),
                self.exchange_pool.clone(),
            ) {
                let eid_vec = eid.to_vec();
                let weak_inner = Arc::downgrade(self);
                let weak_conn = Arc::downgrade(&conn);
                let connection_id = conn.connection_id;
                let job: Job = Box::new(move || {
                    Box::pin(async move {
                        let (Some(inner), Some(current)) = (weak_inner.upgrade(), weak_conn.upgrade()) else {
                            return;
                        };
                        if current.closed.load(Ordering::Acquire)
                            || current.connection_id != connection_id
                            || !mutex_lock(&current.state).eid_activity.contains_key(&eid)
                            || !inner.connected.load(Ordering::Acquire)
                        {
                            return;
                        }
                        callback(eid_vec).await;
                    })
                });
                if !pool.submit(job) {
                    log_callback_error("on_exchange", "callback queue is full or stopped");
                }
            }
        }
        true
    }
}
pub struct Client {
    inner: Arc<ClientInner>,
}
impl Client {
    pub async fn connect(
        host: impl Into<String>,
        port: u16,
        callbacks: ClientCallbacks,
        simultaneous_exchanges: usize,
    ) -> Result<Self> {
        validate_pool_size(simultaneous_exchanges)?;
        let host = host.into();
        let addresses = lookup_host((host.as_str(), port)).await?;
        let deadline = TokioInstant::now() + CONNECT_TIMEOUT;
        let mut connected_stream = None;
        for address in addresses {
            if TokioInstant::now() >= deadline {
                break;
            }
            match timeout_at(deadline, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => {
                    connected_stream = Some(stream);
                    break;
                }
                Ok(Err(_)) | Err(_) => continue,
            }
        }
        let mut stream = connected_stream.ok_or(BackendError::ConnectFailed)?;
        tune_socket(&stream);
        let mut greeting = [0u8; MAGIC_N * 2];
        timeout(GREETING_TIMEOUT, stream.read_exact(&mut greeting))
            .await
            .map_err(|_| BackendError::ConnectFailed)??;
        let mut magic1 = [0u8; MAGIC_N];
        let mut magic2 = [0u8; MAGIC_N];
        magic1.copy_from_slice(&greeting[..MAGIC_N]);
        magic2.copy_from_slice(&greeting[MAGIC_N..]);
        let exchange_pool = if callbacks.on_exchange.is_some() {
            Some(CallbackPool::new(simultaneous_exchanges)?)
        } else {
            None
        };
        let global_memory = Quota::new(MAX_CONNECTION_BUFFERED_BYTES);
        let conn = Connection::new(
            Arc::clone(&global_memory),
            false,
            1,
            Vec::new(),
            None,
        );
        let inner = Arc::new(ClientInner {
            callbacks,
            exchange_pool,
            conn: Mutex::new(Some(Arc::clone(&conn))),
            magic1,
            magic2,
            connected: AtomicBool::new(true),
            stopping: AtomicBool::new(false),
            io_task: Mutex::new(None),
        });
        let weak_inner = Arc::downgrade(&inner);
        let deliver: DeliverFn = Arc::new(move |conn, authed, eid, payload, memory| {
            weak_inner
                .upgrade()
                .map(|inner| inner.deliver_message(conn, authed, eid, payload, memory))
                .unwrap_or(false)
        });
        let task_inner = Arc::clone(&inner);
        let task_conn = Arc::clone(&conn);
        let task = tokio::spawn(async move {
            run_connection(stream, task_conn, magic1, magic2, deliver).await;
            task_inner.connected.store(false, Ordering::Release);
        });
        *mutex_lock(&inner.io_task) = Some(task);
        Ok(Self { inner })
    }
    pub fn handle(&self) -> ClientHandle {
        ClientHandle {
            inner: Arc::downgrade(&self.inner),
        }
    }
    fn connection(&self) -> Result<Arc<Connection>> {
        let inner = self.upgrade()?;

        let connection = mutex_lock(&inner.conn).clone();

        connection.ok_or(BackendError::ConnectionClosed)
    }
    pub fn close(&self) {
        if self.inner.stopping.swap(true, Ordering::AcqRel) {
            return;
        }
        self.inner.connected.store(false, Ordering::Release);
        if let Some(conn) = mutex_lock(&self.inner.conn).clone() {
            conn.close();
        }
        if let Some(pool) = &self.inner.exchange_pool {
            pool.close();
        }
        if let Some(task) = mutex_lock(&self.inner.io_task).take() {
            task.abort();
        }
    }
    pub async fn close_and_wait(&self) {
        self.close();
        if let Some(pool) = &self.inner.exchange_pool {
            pool.close_and_wait().await;
        }
    }
    pub fn send(&self, data: Vec<u8>, requested_eid: Option<Eid>) -> Result<Eid> {
        let conn = self.connection()?;
        if !conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::NotAuthenticated);
        }
        let eid = choose_eid(&conn, requested_eid)?;
        conn.queue_pending(data, eid, true)?;
        Ok(eid)
    }
    pub fn send_handshake(&self, data: Vec<u8>) -> Result<()> {
        let conn = self.connection()?;
        if conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::AlreadyAuthenticated);
        }
        conn.queue_pending(data, [0u8; EID_N], false)
    }
    pub async fn recv(
        &self,
        eid: Eid,
        timeout_duration: Option<Duration>,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.connection()?;
        if !conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::NotAuthenticated);
        }
        let timeout_duration = validate_timeout(timeout_duration)?;
        Ok(pop_message(&conn, Some(eid), true, timeout_duration).await)
    }
    pub async fn recv_handshake(
        &self,
        timeout_duration: Option<Duration>,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.connection()?;
        if conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::AlreadyAuthenticated);
        }
        let timeout_duration = validate_timeout(timeout_duration)?;
        Ok(pop_message(&conn, None, false, timeout_duration).await)
    }
    pub fn auth_finished(&self) -> Result<bool> {
        let conn = self.connection()?;
        conn.authed.store(true, Ordering::Release);
        conn.recv_notify.notify_waiters();
        conn.io_notify.notify_one();
        Ok(true)
    }
    pub fn is_authed(&self) -> bool {
        mutex_lock(&self.inner.conn)
            .as_ref()
            .map(|conn| conn.authed.load(Ordering::Acquire))
            .unwrap_or(false)
    }
    pub fn cid(&self) -> Vec<u8> {
        Vec::new()
    }
    pub fn magic1(&self) -> [u8; MAGIC_N] {
        self.inner.magic1
    }
    pub fn magic2(&self) -> [u8; MAGIC_N] {
        self.inner.magic2
    }
    pub fn set_backpressure(&self, value: bool) -> Result<()> {
        let conn = self.connection()?;
        conn.backpressure.store(value, Ordering::Release);
        conn.io_notify.notify_one();
        Ok(())
    }
}
#[derive(Clone)]
pub struct ClientHandle {
    inner: std::sync::Weak<ClientInner>,
}
impl ClientHandle {
    fn upgrade(&self) -> Result<Arc<ClientInner>> {
        let inner = self.inner.upgrade().ok_or(BackendError::ConnectionClosed)?;
        if !inner.connected.load(Ordering::Acquire)
            || inner.stopping.load(Ordering::Acquire)
        {
            return Err(BackendError::ConnectionClosed);
        }
        Ok(inner)
    }
    fn connection(&self) -> Result<Arc<Connection>> {
        let inner = self.upgrade()?;
        mutex_lock(&inner.conn)
            .clone()
            .ok_or(BackendError::ConnectionClosed)
    }
    pub fn send(&self, data: Vec<u8>, requested_eid: Option<Eid>) -> Result<Eid> {
        let conn = self.connection()?;
        if !conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::NotAuthenticated);
        }
        let eid = choose_eid(&conn, requested_eid)?;
        conn.queue_pending(data, eid, true)?;
        Ok(eid)
    }
    pub fn send_handshake(&self, data: Vec<u8>) -> Result<()> {
        let conn = self.connection()?;
        if conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::AlreadyAuthenticated);
        }
        conn.queue_pending(data, [0u8; EID_N], false)
    }
    pub async fn recv(
        &self,
        eid: Eid,
        timeout_duration: Option<Duration>,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.connection()?;
        if !conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::NotAuthenticated);
        }
        let timeout_duration = validate_timeout(timeout_duration)?;
        Ok(pop_message(&conn, Some(eid), true, timeout_duration).await)
    }
    pub async fn recv_handshake(
        &self,
        timeout_duration: Option<Duration>,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.connection()?;
        if conn.authed.load(Ordering::Acquire) {
            return Err(BackendError::AlreadyAuthenticated);
        }
        let timeout_duration = validate_timeout(timeout_duration)?;
        Ok(pop_message(&conn, None, false, timeout_duration).await)
    }
    pub fn auth_finished(&self) -> Result<bool> {
        let conn = self.connection()?;
        conn.authed.store(true, Ordering::Release);
        conn.recv_notify.notify_waiters();
        conn.io_notify.notify_one();
        Ok(true)
    }
    pub fn is_authed(&self) -> bool {
        self.upgrade()
            .ok()
            .and_then(|inner| mutex_lock(&inner.conn).clone())
            .map(|conn| conn.authed.load(Ordering::Acquire))
            .unwrap_or(false)
    }
    pub fn cid(&self) -> Vec<u8> {
        Vec::new()
    }
    pub fn magic1(&self) -> Result<[u8; MAGIC_N]> {
        Ok(self.upgrade()?.magic1)
    }
    pub fn magic2(&self) -> Result<[u8; MAGIC_N]> {
        Ok(self.upgrade()?.magic2)
    }
    pub fn set_backpressure(&self, value: bool) -> Result<()> {
        let conn = self.connection()?;
        conn.backpressure.store(value, Ordering::Release);
        conn.io_notify.notify_one();
        Ok(())
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if Arc::strong_count(&self.lifetime) == 1 {
            self.inner.stopping.store(true, Ordering::Release);
            self.inner.running.store(false, Ordering::Release);
            if let Some(task) = mutex_lock(&self.inner.accept_task).take() {
                task.abort();
            }
            for conn in mutex_lock(&self.inner.connections).values() {
                conn.close();
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_format_round_trip_layout() {
        let magic1 = *b"MAGICONE";
        let magic2 = *b"MAGICTWO";
        let pending = Pending {
            payload: b"hello".to_vec(),
            eid: *b"12345678",
            authed: true,
            _memory: Lease::new(&Quota::new(1024), &Quota::new(1024), 1).unwrap(),
        };
        let frame = make_frame(&magic1, &magic2, &pending).unwrap();
        assert_eq!(&frame[..8], &magic1);
        assert_eq!(&frame[8..12], &5u32.to_be_bytes());
        assert_eq!(frame[12], b'0');
        assert_eq!(&frame[13..21], b"12345678");
        assert_eq!(&frame[21..26], b"hello");
        assert_eq!(&frame[26..], &magic2);
    }
    #[test]
    fn unauthenticated_wire_format_layout() {
        let magic1 = *b"MAGICONE";
        let magic2 = *b"MAGICTWO";
        let pending = Pending {
            payload: b"hello".to_vec(),
            eid: [0u8; EID_N],
            authed: false,
            _memory: Lease::new(&Quota::new(1024), &Quota::new(1024), 1).unwrap(),
        };
        let frame = make_frame(&magic1, &magic2, &pending).unwrap();
        assert_eq!(&frame[..8], &magic1);
        assert_eq!(&frame[8..10], &5u16.to_be_bytes());
        assert_eq!(&frame[10..15], b"hello");
        assert_eq!(&frame[15..], &magic2);
    }
    #[test]
    fn an_existing_eid_is_refreshed_not_recreated() {
        let conn = Connection::new(Quota::new(1024), false, 1, Vec::new(), None);
        let eid = *b"12345678";
        assert_eq!(conn.touch_eid(eid), EidTouch::Fresh);
        assert_eq!(conn.touch_eid(eid), EidTouch::Existing);
        assert_eq!(mutex_lock(&conn.state).eid_activity.len(), 1);
    }
    #[test]
    fn quota_reservations_are_released() {
        let global = Quota::new(10);
        let local = Quota::new(10);
        {
            let _lease = Lease::new(&global, &local, 7).unwrap();
            assert_eq!(global.used.load(Ordering::Acquire), 7);
            assert_eq!(local.used.load(Ordering::Acquire), 7);
            assert!(Lease::new(&global, &local, 4).is_none());
        }
        assert_eq!(global.used.load(Ordering::Acquire), 0);
        assert_eq!(local.used.load(Ordering::Acquire), 0);
    }
}