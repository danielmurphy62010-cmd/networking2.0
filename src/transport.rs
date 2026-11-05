//! L1 TCP transport: greeting, framing, queueing, eid routing and callbacks.
//!
//! The implementation intentionally uses per-socket reader/writer threads
//! rather than mirroring the original single poll thread. The framing, queue,
//! admission, eid and callback semantics remain those of the supplied spec.

use crate::crypto::random_bytes;
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{sync_channel, Receiver, SyncSender, TrySendError},
        Arc, Condvar, Mutex, Weak,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use thiserror::Error;
use socket2::{Domain, Protocol as SocketProtocol, SockRef, Socket, Type};

pub const MAX_UNAUTH_PAYLOAD: usize = 65_535;
pub const MAX_AUTH_PAYLOAD: usize = 1 << 25;
pub const QUEUE_LIMIT: usize = 16;
pub const MAX_INPUT_BUFFER: usize = 32 * 1024 * 1024;
pub const MAX_ACTIVE_EIDS_PER_CONNECTION: usize = 2048;
pub const EID_TTL: Duration = Duration::from_secs(60);
pub const UNAUTH_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_CID_BYTES: usize = 256;
const READ_CHUNK: usize = 16 * 1024;
const READ_TICK: Duration = Duration::from_millis(20);
const WRITE_CHUNK: usize = 64 * 1024;
const SERVER_CONNECTION_LIMIT: usize = 200;
const SERVER_UNAUTH_LIMIT: usize = 128;
const PER_PEER_CONNECTION_LIMIT: usize = 64;
const PER_PEER_RATE_LIMIT: usize = 120;
const MAX_PEER_BUCKETS: usize = 4096;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("unknown client")]
    UnknownClient,
    #[error("unknown temporary client")]
    UnknownTemporaryClient,
    #[error("connection is closed")]
    Closed,
    #[error("connection is not authenticated; use send_handshake")]
    NotAuthenticated,
    #[error("connection is authenticated; use send")]
    AlreadyAuthenticated,
    #[error("invalid exchange id: it must be exactly 8 bytes")]
    InvalidEid,
    #[error("invalid client id: it must contain 1 to 256 bytes")]
    InvalidCid,
    #[error("exchange-id limit reached")]
    EidLimit,
    #[error("send queue is full")]
    SendQueueFull,
    #[error("payload exceeds the maximum for this protocol phase")]
    PayloadTooLarge,
    #[error("connection memory budget exhausted")]
    MemoryBudget,
    #[error("server is already running")]
    AlreadyRunning,
    #[error("server has already been stopped")]
    Stopped,
    #[error("I/O error: {0}")]
    Io(String),
    #[error("invalid timeout; expected 0 through 365 days")]
    InvalidTimeout,
    #[error("callback worker pool is full or stopped")]
    PoolFull,
}

impl From<io::Error> for TransportError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

pub type TResult<T> = Result<T, TransportError>;
type Job = Box<dyn FnOnce() + Send + 'static>;

/// Small bounded callback pool. Workers are created on the first submitted job.
struct WorkerPool {
    workers: usize,
    queue_limit: usize,
    sender: SyncSender<Option<Job>>,
    receiver: Arc<Mutex<Receiver<Option<Job>>>>,
    started: AtomicBool,
    stopped: AtomicBool,
}

impl WorkerPool {
    fn new(workers: usize) -> Arc<Self> {
        let count = workers.clamp(1, 64);
        let limit = (count * 64).clamp(32, 1024);
        Self::new_with_limit(count, limit)
    }

    fn new_with_limit(workers: usize, limit: usize) -> Arc<Self> {
        let count = workers.clamp(1, 64);
        let (sender, receiver) = sync_channel::<Option<Job>>(limit.max(1));
        Arc::new(Self {
            workers: count,
            queue_limit: limit,
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
            started: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
        })
    }

    fn ensure_started(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        for _ in 0..self.workers {
            let receiver = Arc::clone(&self.receiver);
            thread::spawn(move || loop {
                let message = {
                    let lock = receiver.lock().unwrap_or_else(|e| e.into_inner());
                    lock.recv()
                };
                match message {
                    Ok(Some(job)) => {
                        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)).is_err() {
                            eprintln!("network2: callback worker job panicked");
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            });
        }
    }

    fn submit(self: &Arc<Self>, job: Job) -> Result<(), TransportError> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(TransportError::PoolFull);
        }
        self.ensure_started();
        match self.sender.try_send(Some(job)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                Err(TransportError::PoolFull)
            }
        }
    }

    fn stop(&self) {
        if self.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        if self.started.load(Ordering::Acquire) {
            for _ in 0..self.workers {
                let _ = self.sender.send(None);
            }
        }
    }

    #[allow(dead_code)]
    fn capacity(&self) -> usize {
        self.queue_limit
    }
}

struct Message {
    authenticated: bool,
    eid: Option<[u8; 8]>,
    payload: Vec<u8>,
    _lease: MemoryLease,
}

struct Pending {
    authenticated: bool,
    eid: Option<[u8; 8]>,
    payload: Vec<u8>,
    _lease: MemoryLease,
}

struct MemoryLease {
    used: Arc<AtomicUsize>,
    bytes: usize,
}

impl MemoryLease {
    fn acquire(used: &Arc<AtomicUsize>, bytes: usize, limit: usize) -> Option<Self> {
        let mut current = used.load(Ordering::Acquire);
        loop {
            let next = current.checked_add(bytes)?;
            if next > limit {
                return None;
            }
            match used.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(Self { used: Arc::clone(used), bytes }),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for MemoryLease {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

struct ConnState {
    authenticated: bool,
    closed: bool,
    backpressure: bool,
    cid: Option<Vec<u8>>,
    receive: VecDeque<Message>,
    send: VecDeque<Pending>,
    input: Vec<u8>,
    eid_activity: HashMap<[u8; 8], Instant>,
    handshake_permits: usize,
    first_unauth_seen: bool,
    last_cleanup: Instant,
    queued_bytes: usize,
}

type HandshakeCallback = Arc<dyn Fn(Vec<u8>) + Send + Sync + 'static>;
type ServerExchangeCallback = Arc<dyn Fn(Vec<u8>, [u8; 8]) + Send + Sync + 'static>;
type ClientExchangeCallback = Arc<dyn Fn([u8; 8]) + Send + Sync + 'static>;
type CloseCallback = Arc<dyn Fn(u64, Option<Vec<u8>>) + Send + Sync + 'static>;

struct Connection {
    id: u64,
    temp_id: Option<Vec<u8>>,
    magic1: [u8; 8],
    magic2: [u8; 8],
    state: Mutex<ConnState>,
    changed: Condvar,
    shutdown_stream: TcpStream,
    global_memory: Arc<AtomicUsize>,
    global_limit: usize,
    closed_notified: AtomicBool,
    accepted_at: Instant,
    is_server_side: bool,
    on_handshake: Option<HandshakeCallback>,
    on_server_exchange: Option<ServerExchangeCallback>,
    on_client_exchange: Option<ClientExchangeCallback>,
    on_close: Option<CloseCallback>,
}

impl Connection {
    fn new(
        id: u64,
        temp_id: Option<Vec<u8>>,
        stream: &TcpStream,
        global_memory: Arc<AtomicUsize>,
        global_limit: usize,
        magic1: [u8; 8],
        magic2: [u8; 8],
        is_server_side: bool,
        on_handshake: Option<HandshakeCallback>,
        on_server_exchange: Option<ServerExchangeCallback>,
        on_client_exchange: Option<ClientExchangeCallback>,
        on_close: Option<CloseCallback>,
    ) -> TResult<Arc<Self>> {
        let shutdown_stream = stream.try_clone()?;
        Ok(Arc::new(Self {
            id,
            temp_id,
            magic1,
            magic2,
            state: Mutex::new(ConnState {
                authenticated: false,
                closed: false,
                backpressure: false,
                cid: None,
                receive: VecDeque::with_capacity(QUEUE_LIMIT),
                send: VecDeque::with_capacity(QUEUE_LIMIT),
                input: Vec::with_capacity(4096),
                eid_activity: HashMap::new(),
                handshake_permits: 0,
                first_unauth_seen: false,
                last_cleanup: Instant::now(),
                queued_bytes: 0,
            }),
            changed: Condvar::new(),
            shutdown_stream,
            global_memory,
            global_limit,
            closed_notified: AtomicBool::new(false),
            accepted_at: Instant::now(),
            is_server_side,
            on_handshake,
            on_server_exchange,
            on_client_exchange,
            on_close,
        }))
    }

    fn start(self: &Arc<Self>, mut reader: TcpStream, mut writer: TcpStream) {
        let read_conn = Arc::clone(self);
        let write_conn = Arc::clone(self);
        let _ = reader.set_read_timeout(Some(READ_TICK));
        let _ = writer.set_write_timeout(Some(READ_TICK));
        thread::Builder::new()
            .name(format!("network2-rx-{}", self.id))
            .spawn(move || read_conn.reader_loop(&mut reader));
        thread::Builder::new()
            .name(format!("network2-tx-{}", self.id))
            .spawn(move || write_conn.writer_loop(&mut writer));
    }

    fn is_closed(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).closed
    }

    fn is_authenticated(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .authenticated
    }

    fn is_eid_active(&self, eid: [u8; 8]) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !state.closed && state.eid_activity.contains_key(&eid)
    }

    fn close(&self) {
        let notify = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.closed {
                false
            } else {
                state.closed = true;
                state.receive.clear();
                state.send.clear();
                state.queued_bytes = 0;
                self.changed.notify_all();
                true
            }
        };
        let _ = self.shutdown_stream.shutdown(Shutdown::Both);
        if notify && !self.closed_notified.swap(true, Ordering::AcqRel) {
            if let Some(callback) = &self.on_close {
                let cid = self
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .cid
                    .clone();
                callback(self.id, cid);
            }
        }
    }

    fn touch_eid(state: &mut ConnState, eid: [u8; 8], now: Instant) -> TResult<bool> {
        Self::expire_eids(state, now);
        if let Some(last) = state.eid_activity.get_mut(&eid) {
            *last = now;
            return Ok(false);
        }
        if state.eid_activity.len() >= MAX_ACTIVE_EIDS_PER_CONNECTION {
            return Err(TransportError::EidLimit);
        }
        state.eid_activity.insert(eid, now);
        Ok(true)
    }

    fn expire_eids(state: &mut ConnState, now: Instant) {
        if now.duration_since(state.last_cleanup) < Duration::from_secs(1) {
            return;
        }
        state.last_cleanup = now;
        let expired: Vec<[u8; 8]> = state
            .eid_activity
            .iter()
            .filter_map(|(eid, last)| {
                (now.duration_since(*last) >= EID_TTL).then_some(*eid)
            })
            .collect();
        if expired.is_empty() {
            return;
        }
        for eid in &expired {
            state.eid_activity.remove(eid);
        }
        let removed_receive: usize = state
            .receive
            .iter()
            .filter(|message| message.eid.is_some_and(|eid| expired.contains(&eid)))
            .map(|message| message.payload.len().saturating_add(64))
            .sum();
        let removed_send: usize = state
            .send
            .iter()
            .filter(|pending| pending.eid.is_some_and(|eid| expired.contains(&eid)))
            .map(|pending| pending.payload.len().saturating_add(64))
            .sum();
        state
            .receive
            .retain(|message| message.eid.is_none_or(|eid| !expired.contains(&eid)));
        state
            .send
            .retain(|pending| pending.eid.is_none_or(|eid| !expired.contains(&eid)));
        state.queued_bytes = state.queued_bytes.saturating_sub(removed_receive + removed_send);
    }

    fn queue_send(&self, payload: Vec<u8>, eid: Option<[u8; 8]>, authenticated: bool) -> TResult<[u8; 8]> {
        let cap = if authenticated {
            MAX_AUTH_PAYLOAD
        } else {
            MAX_UNAUTH_PAYLOAD
        };
        if payload.len() > cap {
            return Err(TransportError::PayloadTooLarge);
        }
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return Err(TransportError::Closed);
        }
        if state.authenticated != authenticated {
            return Err(if authenticated {
                TransportError::NotAuthenticated
            } else {
                TransportError::AlreadyAuthenticated
            });
        }
        if state.send.len() >= QUEUE_LIMIT {
            return Err(TransportError::SendQueueFull);
        }
        let eid = if authenticated {
            let chosen = match eid {
                Some(value) => value,
                None => {
                    let mut chosen = None;
                    for _ in 0..16 {
                        let bytes = random_bytes(8).map_err(|e| TransportError::Io(e.to_string()))?;
                        let candidate: [u8; 8] = bytes.try_into().expect("8 random bytes");
                        if !state.eid_activity.contains_key(&candidate) {
                            chosen = Some(candidate);
                            break;
                        }
                    }
                    chosen.ok_or(TransportError::EidLimit)?
                }
            };
            Self::touch_eid(&mut state, chosen, now)?;
            Some(chosen)
        } else {
            None
        };
        let needed = payload.len().saturating_add(64);
        if state.queued_bytes.saturating_add(needed) > 128 * 1024 * 1024 {
            return Err(TransportError::MemoryBudget);
        }
        let lease = MemoryLease::acquire(&self.global_memory, needed, self.global_limit)
            .ok_or(TransportError::MemoryBudget)?;
        state.queued_bytes += needed;
        state.send.push_back(Pending {
            authenticated,
            eid,
            payload,
            _lease: lease,
        });
        self.changed.notify_all();
        Ok(eid.unwrap_or([0u8; 8]))
    }

    fn recv(
        &self,
        authenticated: bool,
        eid: Option<[u8; 8]>,
        timeout: Option<Duration>,
    ) -> TResult<Option<Vec<u8>>> {
        if timeout.is_some_and(|t| t > Duration::from_secs(365 * 24 * 60 * 60)) {
            return Err(TransportError::InvalidTimeout);
        }
        if authenticated && eid.is_none() {
            return Err(TransportError::InvalidEid);
        }
        let start = Instant::now();
        let mut permit_requested = false;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if state.closed || state.authenticated != authenticated {
                return Ok(None);
            }
            if let Some(index) = state.receive.iter().position(|message| {
                message.authenticated == authenticated
                    && (!authenticated || message.eid == eid)
            }) {
                let message = state.receive.remove(index).expect("position exists");
                state.queued_bytes = state
                    .queued_bytes
                    .saturating_sub(message.payload.len().saturating_add(64));
                self.changed.notify_all();
                return Ok(Some(message.payload));
            }
            if !authenticated && !permit_requested {
                // Unaudited frames are parsed only when the L3 handshake asks
                // for its next item. This preserves the phase switch ordering
                // without inserting a new wire marker.
                state.handshake_permits = state.handshake_permits.saturating_add(1);
                permit_requested = true;
                self.changed.notify_all();
            }
            match timeout {
                None => {
                    state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
                }
                Some(limit) => {
                    let remaining = limit.saturating_sub(start.elapsed());
                    if remaining.is_zero() {
                        return Ok(None);
                    }
                    let (next, wait) = self
                        .changed
                        .wait_timeout(state, remaining)
                        .unwrap_or_else(|e| e.into_inner());
                    state = next;
                    if wait.timed_out() {
                        return Ok(None);
                    }
                }
            }
        }
    }

    fn auth_finished(&self, cid: Option<Vec<u8>>) -> TResult<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return Err(TransportError::Closed);
        }
        state.cid = cid;
        state.authenticated = true;
        state.handshake_permits = 0;
        self.changed.notify_all();
        Ok(())
    }

    fn set_backpressure(&self, enabled: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.backpressure = enabled;
        self.changed.notify_all();
    }

    fn parse_available(&self) {
        let mut server_handshake = false;
        let mut server_events: Vec<(Vec<u8>, [u8; 8])> = Vec::new();
        let mut client_events: Vec<[u8; 8]> = Vec::new();
        let mut should_close = false;
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.closed || state.receive.len() >= QUEUE_LIMIT {
                return;
            }
            Self::expire_eids(&mut state, Instant::now());
            let mut offset = 0usize;
            let mut consumed = 0usize;
            let mut frames = 0usize;
            let mut steps = 0usize;
            while frames < 32 && steps < 128 {
                steps += 1;
                if state.receive.len() >= QUEUE_LIMIT {
                    break;
                }
                let authenticated = state.authenticated;
                if !authenticated && state.first_unauth_seen && state.handshake_permits == 0 {
                    break;
                }
                if offset >= state.input.len() {
                    break;
                }
                let found = find_subslice(&state.input[offset..], &self.magic1);
                let Some(relative) = found else {
                    let tail = longest_magic_prefix_suffix(&state.input[offset..], &self.magic1);
                    let drop_len = state.input.len().saturating_sub(offset + tail);
                    offset += drop_len;
                    consumed = offset;
                    break;
                };
                offset += relative;
                if offset > consumed {
                    consumed = offset;
                }
                let header_len = if authenticated { 13 } else { 2 };
                if state.input.len().saturating_sub(offset) < 8 + header_len {
                    break;
                }
                let header_start = offset + 8;
                let (payload_len, eid) = if authenticated {
                    let len = u32::from_be_bytes(
                        state.input[header_start..header_start + 4]
                            .try_into()
                            .expect("4-byte length"),
                    ) as usize;
                    let flag = state.input[header_start + 4];
                    if flag != b'0' && flag != b'1' {
                        offset += 1;
                        consumed = offset;
                        continue;
                    }
                    if len > MAX_AUTH_PAYLOAD {
                        offset += 1;
                        consumed = offset;
                        continue;
                    }
                    let mut exchange = [0u8; 8];
                    exchange.copy_from_slice(&state.input[header_start + 5..header_start + 13]);
                    (len, Some(exchange))
                } else {
                    let len = u16::from_be_bytes(
                        state.input[header_start..header_start + 2]
                            .try_into()
                            .expect("2-byte length"),
                    ) as usize;
                    if len > MAX_UNAUTH_PAYLOAD {
                        offset += 1;
                        consumed = offset;
                        continue;
                    }
                    (len, None)
                };
                let frame_size = 8usize
                    .saturating_add(header_len)
                    .saturating_add(payload_len)
                    .saturating_add(8);
                if state.input.len().saturating_sub(offset) < frame_size {
                    break;
                }
                let trailer_start = offset + frame_size - 8;
                if state.input[trailer_start..trailer_start + 8] != self.magic2 {
                    let search_start = offset + 8;
                    let search_end = trailer_start;
                    let next = if search_start < search_end {
                        find_subslice(&state.input[search_start..search_end], &self.magic1)
                    } else {
                        None
                    };
                    if let Some(relative_next) = next {
                        offset = search_start + relative_next;
                        consumed = offset;
                    } else {
                        offset += frame_size;
                        consumed = offset;
                    }
                    frames += 1;
                    continue;
                }
                if state.queued_bytes.saturating_add(payload_len + 64) > 128 * 1024 * 1024 {
                    eprintln!(
                        "network2: closing connection {}: receive queue memory limit exceeded (queued={} incoming={})",
                        self.id, state.queued_bytes, payload_len + 64
                    );
                    should_close = true;
                    break;
                }
                let Some(lease) = MemoryLease::acquire(
                    &self.global_memory,
                    payload_len + 64,
                    self.global_limit,
                ) else {
                    eprintln!(
                        "network2: closing connection {}: global receive memory budget exhausted (incoming={})",
                        self.id, payload_len + 64
                    );
                    should_close = true;
                    break;
                };
                let payload_start = header_start + header_len;
                let payload = state.input[payload_start..payload_start + payload_len].to_vec();
                if let Some(exchange) = eid {
                    match Self::touch_eid(&mut state, exchange, Instant::now()) {
                        Ok(fresh) => {
                            state.queued_bytes += payload_len + 64;
                            state.receive.push_back(Message {
                                authenticated: true,
                                eid: Some(exchange),
                                payload,
                                _lease: lease,
                            });
                            if fresh {
                                if self.is_server_side {
                                    if let Some(cid) = state.cid.clone() {
                                        server_events.push((cid, exchange));
                                    }
                                } else {
                                    client_events.push(exchange);
                                }
                            }
                        }
                        Err(TransportError::EidLimit) => {
                            eprintln!(
                                "network2: closing connection {}: active EID limit reached (limit={})",
                                self.id, MAX_ACTIVE_EIDS_PER_CONNECTION
                            );
                            should_close = true;
                            break;
                        }
                        Err(_) => {
                            offset += frame_size;
                            consumed = offset;
                            frames += 1;
                            continue;
                        }
                    }
                } else {
                    state.queued_bytes += payload_len + 64;
                    state.receive.push_back(Message {
                        authenticated: false,
                        eid: None,
                        payload,
                        _lease: lease,
                    });
                    if !state.first_unauth_seen {
                        state.first_unauth_seen = true;
                        if self.is_server_side {
                            server_handshake = true;
                        }
                    }
                    if state.handshake_permits > 0 {
                        state.handshake_permits -= 1;
                    }
                }
                offset += frame_size;
                consumed = offset;
                frames += 1;
            }
            if consumed > 0 {
                state.input.drain(..consumed);
            }
            if state.input.is_empty() && state.input.capacity() > 256 * 1024 {
                state.input = Vec::with_capacity(4096);
            } else if state.input.capacity() > 1024 * 1024
                && state.input.len() < state.input.capacity() / 8
            {
                // Store the target before the mutable method call to avoid
                // overlapping immutable and mutable borrows of `state.input`.
                let target_capacity = state.input.len().max(4096);
                state.input.shrink_to(target_capacity);
            }
            if state.input.len() > MAX_INPUT_BUFFER {
                should_close = true;
            }
            self.changed.notify_all();
        }
        if server_handshake {
            if let (Some(callback), Some(temp_id)) = (&self.on_handshake, &self.temp_id) {
                callback(temp_id.clone());
            }
        }
        if let Some(callback) = &self.on_server_exchange {
            for (cid, eid) in server_events {
                callback(cid, eid);
            }
        }
        if let Some(callback) = &self.on_client_exchange {
            for eid in client_events {
                callback(eid);
            }
        }
        if should_close {
            self.close();
        }
    }

    fn reader_loop(self: Arc<Self>, stream: &mut TcpStream) {
        let mut buffer = [0u8; READ_CHUNK];
        loop {
            if self.is_closed() {
                break;
            }
            {
                let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if self.is_server_side
                    && !state.authenticated
                    && self.accepted_at.elapsed() > UNAUTH_TIMEOUT
                {
                    drop(state);
                    self.close();
                    break;
                }
                if state.backpressure || state.receive.len() >= QUEUE_LIMIT {
                    drop(state);
                    self.parse_available();
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
            }
            match stream.read(&mut buffer) {
                Ok(0) => {
                    self.close();
                    break;
                }
                Ok(count) => {
                    let overflow = {
                        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                        if state.input.len().saturating_add(count) > MAX_INPUT_BUFFER {
                            true
                        } else {
                            state.input.extend_from_slice(&buffer[..count]);
                            false
                        }
                    };
                    if overflow {
                        self.close();
                        break;
                    }
                    self.parse_available();
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut
                        || error.kind() == io::ErrorKind::Interrupted =>
                {
                    self.parse_available();
                }
                Err(_) => {
                    self.close();
                    break;
                }
            }
        }
    }

    fn writer_loop(self: Arc<Self>, stream: &mut TcpStream) {
        loop {
            let pending = {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    if state.closed {
                        return;
                    }
                    if let Some(pending) = state.send.pop_front() {
                        state.queued_bytes = state
                            .queued_bytes
                            .saturating_sub(pending.payload.len().saturating_add(64));
                        break pending;
                    }
                    state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
                }
            };
            let frame = make_frame(
                &self.magic1,
                &self.magic2,
                pending.authenticated,
                pending.eid,
                &pending.payload,
            );
            let mut offset = 0usize;
            while offset < frame.len() {
                let end = (offset + WRITE_CHUNK).min(frame.len());
                match stream.write(&frame[offset..end]) {
                    Ok(0) => {
                        self.close();
                        return;
                    }
                    Ok(count) => offset += count,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            || error.kind() == io::ErrorKind::TimedOut
                            || error.kind() == io::ErrorKind::Interrupted =>
                    {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => {
                        self.close();
                        return;
                    }
                }
            }
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn longest_magic_prefix_suffix(buffer: &[u8], magic: &[u8; 8]) -> usize {
    (1..=7.min(buffer.len()))
        .rev()
        .find(|length| buffer[buffer.len() - length..] == magic[..*length])
        .unwrap_or(0)
}

fn make_frame(
    magic1: &[u8; 8],
    magic2: &[u8; 8],
    authenticated: bool,
    eid: Option<[u8; 8]>,
    payload: &[u8],
) -> Vec<u8> {
    let header = if authenticated { 13 } else { 2 };
    let mut frame = Vec::with_capacity(8 + header + payload.len() + 8);
    frame.extend_from_slice(magic1);
    if authenticated {
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.push(b'0');
        frame.extend_from_slice(&eid.unwrap_or([0u8; 8]));
    } else {
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame.extend_from_slice(magic2);
    frame
}

struct PeerStat {
    live: usize,
    attempts: VecDeque<Instant>,
}

struct ServerInner {
    host: String,
    port: u16,
    magic1: [u8; 8],
    magic2: [u8; 8],
    running: AtomicBool,
    stopped: AtomicBool,
    next_id: AtomicU64,
    listener_thread: Mutex<Option<JoinHandle<()>>>,
    connections: Mutex<HashMap<u64, Arc<Connection>>>,
    temporary: Mutex<HashMap<Vec<u8>, Arc<Connection>>>,
    permanent: Mutex<HashMap<Vec<u8>, Arc<Connection>>>,
    peers: Mutex<HashMap<IpAddr, PeerStat>>,
    global_memory: Arc<AtomicUsize>,
    handshake_pool: Arc<WorkerPool>,
    exchange_pool: Arc<WorkerPool>,
    disconnect_pool: Arc<WorkerPool>,
    handshake_callback: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    exchange_callback: Arc<dyn Fn(Vec<u8>, [u8; 8]) + Send + Sync>,
    disconnect_callback: Arc<dyn Fn(Vec<u8>, u64) + Send + Sync>,
}

#[derive(Clone)]
pub struct TransportServer {
    inner: Arc<ServerInner>,
}

impl TransportServer {
    pub fn new(
        host: String,
        port: u16,
        simult_handshakes: usize,
        simult_exchanges: usize,
        handshake_callback: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
        exchange_callback: Arc<dyn Fn(Vec<u8>, [u8; 8]) + Send + Sync>,
        disconnect_callback: Arc<dyn Fn(Vec<u8>, u64) + Send + Sync>,
    ) -> TResult<Self> {
        let first = random_bytes(8).map_err(|e| TransportError::Io(e.to_string()))?;
        let mut second = random_bytes(8).map_err(|e| TransportError::Io(e.to_string()))?;
        while first == second {
            second = random_bytes(8).map_err(|e| TransportError::Io(e.to_string()))?;
        }
        let magic1: [u8; 8] = first.try_into().expect("8 random bytes");
        let magic2: [u8; 8] = second.try_into().expect("8 random bytes");
        if !(1..=64).contains(&simult_handshakes) || !(1..=64).contains(&simult_exchanges) {
            return Err(TransportError::Io("pool worker count must be 1 through 64".into()));
        }
        Ok(Self {
            inner: Arc::new(ServerInner {
                host,
                port,
                magic1,
                magic2,
                running: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                next_id: AtomicU64::new(1),
                listener_thread: Mutex::new(None),
                connections: Mutex::new(HashMap::new()),
                temporary: Mutex::new(HashMap::new()),
                permanent: Mutex::new(HashMap::new()),
                peers: Mutex::new(HashMap::new()),
                global_memory: Arc::new(AtomicUsize::new(0)),
                handshake_pool: WorkerPool::new(simult_handshakes),
                exchange_pool: WorkerPool::new(simult_exchanges),
                // Disconnect cleanup must not be dropped during a burst of
                // simultaneous connection closes.
                disconnect_pool: WorkerPool::new_with_limit(1, 4096),
                handshake_callback,
                exchange_callback,
                disconnect_callback,
            }),
        })
    }

    pub fn start(&self) -> TResult<()> {
        if self.inner.stopped.load(Ordering::Acquire) {
            return Err(TransportError::Stopped);
        }
        if self.inner.running.swap(true, Ordering::AcqRel) {
            return Err(TransportError::AlreadyRunning);
        }
        let bind_host = if self.inner.host.is_empty() {
            "0.0.0.0".to_string()
        } else {
            self.inner.host.clone()
        };
        let addresses: Vec<SocketAddr> = match (bind_host.as_str(), self.inner.port).to_socket_addrs() {
            Ok(values) => values.collect(),
            Err(error) => {
                self.inner.running.store(false, Ordering::Release);
                return Err(error.into());
            }
        };
        let mut listener = None;
        for address in addresses {
            let domain = if address.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
            let Ok(socket) = Socket::new(domain, Type::STREAM, Some(SocketProtocol::TCP)) else {
                continue;
            };
            let _ = socket.set_reuse_address(true);
            if socket.bind(&address.into()).is_ok() && socket.listen(128).is_ok() {
                listener = Some(TcpListener::from(socket));
                break;
            }
        }
        let listener = match listener {
            Some(value) => value,
            None => {
                self.inner.running.store(false, Ordering::Release);
                return Err(TransportError::Io("could not bind any resolved address".into()));
            }
        };
        if let Err(error) = listener.set_nonblocking(true) {
            self.inner.running.store(false, Ordering::Release);
            return Err(error.into());
        }
        let inner = Arc::clone(&self.inner);
        let thread = match thread::Builder::new()
            .name("network2-accept".into())
            .spawn(move || accept_loop(inner, listener))
        {
            Ok(handle) => handle,
            Err(error) => {
                self.inner.running.store(false, Ordering::Release);
                return Err(TransportError::Io(error.to_string()));
            }
        };
        *self
            .inner
            .listener_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(thread);
        Ok(())
    }

    pub fn magic1(&self) -> Vec<u8> {
        self.inner.magic1.to_vec()
    }

    pub fn magic2(&self) -> Vec<u8> {
        self.inner.magic2.to_vec()
    }

    pub fn connection_id(&self, temp_cid: &[u8]) -> TResult<u64> {
        self.inner
            .temporary
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(temp_cid)
            .map(|conn| conn.id)
            .ok_or(TransportError::UnknownTemporaryClient)
    }

    pub fn close_handshake(&self, temp_cid: &[u8]) {
        if let Some(conn) = self
            .inner
            .temporary
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(temp_cid)
            .cloned()
        {
            conn.close();
        }
    }

    pub fn send_handshake(&self, temp_cid: &[u8], payload: Vec<u8>) -> TResult<()> {
        let conn = self
            .inner
            .temporary
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(temp_cid)
            .cloned()
            .ok_or(TransportError::UnknownTemporaryClient)?;
        conn.queue_send(payload, None, false)?;
        Ok(())
    }

    pub fn recv_handshake(&self, temp_cid: &[u8], timeout: Option<Duration>) -> TResult<Option<Vec<u8>>> {
        let conn = self
            .inner
            .temporary
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(temp_cid)
            .cloned()
            .ok_or(TransportError::UnknownTemporaryClient)?;
        conn.recv(false, None, timeout)
    }

    pub fn auth_finished(
        &self,
        temp_cid: &[u8],
        new_cid: Vec<u8>,
        confirmation_payload: Option<Vec<u8>>,
    ) -> TResult<()> {
        if new_cid.is_empty() || new_cid.len() > MAX_CID_BYTES {
            return Err(TransportError::InvalidCid);
        }
        let conn = self
            .inner
            .temporary
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(temp_cid)
            .cloned()
            .ok_or(TransportError::UnknownTemporaryClient)?;
        if let Some(payload) = confirmation_payload {
            conn.queue_send(payload, None, false)?;
        }
        // Publish the permanent id while holding its map lock and transition
        // the connection state before releasing it. If the socket closes in
        // this window, the close callback waits for the map lock and removes
        // the just-published id instead of racing a stale insertion.
        let mut permanent = self.inner.permanent.lock().unwrap_or_else(|e| e.into_inner());
        if permanent.contains_key(&new_cid) {
            return Err(TransportError::Io("client id is already in use".into()));
        }
        conn.auth_finished(Some(new_cid.clone()))?;
        permanent.insert(new_cid.clone(), Arc::clone(&conn));
        drop(permanent);
        self.inner
            .temporary
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(temp_cid);
        Ok(())
    }

    pub fn send(&self, cid: &[u8], payload: Vec<u8>, eid: Option<Vec<u8>>) -> TResult<Vec<u8>> {
        let conn = self
            .inner
            .permanent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(cid)
            .cloned()
            .ok_or(TransportError::UnknownClient)?;
        let eid = eid.as_deref().map(parse_eid).transpose()?;
        Ok(conn.queue_send(payload, eid, true)?.to_vec())
    }

    pub fn recv(&self, cid: &[u8], eid: &[u8], timeout: Option<Duration>) -> TResult<Option<Vec<u8>>> {
        let conn = self
            .inner
            .permanent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(cid)
            .cloned()
            .ok_or(TransportError::UnknownClient)?;
        conn.recv(true, Some(parse_eid(eid)?), timeout)
    }

    pub fn is_authed(&self, cid: &[u8]) -> bool {
        self.inner
            .permanent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(cid)
            .is_some_and(|conn| conn.is_authenticated() && !conn.is_closed())
    }

    pub fn set_backpressure(&self, cid: &[u8], enabled: bool) -> TResult<()> {
        let conn = self
            .inner
            .permanent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(cid)
            .cloned()
            .ok_or(TransportError::UnknownClient)?;
        conn.set_backpressure(enabled);
        Ok(())
    }

    pub fn close_client(&self, cid: &[u8]) -> TResult<()> {
        let conn = self
            .inner
            .permanent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(cid)
            .ok_or(TransportError::UnknownClient)?;
        conn.close();
        Ok(())
    }

    pub fn connection_ids(&self) -> Vec<Vec<u8>> {
        self.inner
            .permanent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    pub fn stop(&self) {
        if self.inner.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        self.inner.running.store(false, Ordering::Release);
        if let Some(handle) = self
            .inner
            .listener_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = handle.join();
        }
        let all: Vec<Arc<Connection>> = self
            .inner
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        for conn in all {
            conn.close();
        }
        self.inner
            .temporary
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.inner
            .permanent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.inner.handshake_pool.stop();
        self.inner.exchange_pool.stop();
        // Disconnect notifications are queued before this drain/stop.
        self.inner.disconnect_pool.stop();
    }
}

fn accept_loop(inner: Arc<ServerInner>, listener: TcpListener) {
    while inner.running.load(Ordering::Acquire) {
        let mut accepted = 0usize;
        while accepted < 32 {
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    accepted += 1;
                    if !admit_peer(&inner, peer.ip()) {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                    let (total, unauth) = {
                        let connections = inner.connections.lock().unwrap_or_else(|e| e.into_inner());
                        let total = connections.len();
                        let unauth = connections.values().filter(|c| !c.is_authenticated()).count();
                        (total, unauth)
                    };
                    if total >= SERVER_CONNECTION_LIMIT || unauth >= SERVER_UNAUTH_LIMIT {
                        let _ = stream.shutdown(Shutdown::Both);
                        decrement_peer(&inner, peer.ip());
                        continue;
                    }
                    let _ = stream.set_nodelay(true);
                    {
                        let socket = SockRef::from(&stream);
                        let _ = socket.set_recv_buffer_size(64 * 1024);
                        let _ = socket.set_send_buffer_size(64 * 1024);
                        let _ = socket.set_keepalive(true);
                    }
                    let _ = stream.set_read_timeout(Some(READ_TICK));
                    let _ = stream.set_write_timeout(Some(READ_TICK));
                    if stream
                        .write_all(&[inner.magic1.as_slice(), inner.magic2.as_slice()].concat())
                        .is_err()
                    {
                        let _ = stream.shutdown(Shutdown::Both);
                        decrement_peer(&inner, peer.ip());
                        continue;
                    }
                    if let Err(_) = make_server_connection(&inner, stream, peer.ip()) {
                        decrement_peer(&inner, peer.ip());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn admit_peer(inner: &Arc<ServerInner>, ip: IpAddr) -> bool {
    let now = Instant::now();
    let mut peers = inner.peers.lock().unwrap_or_else(|e| e.into_inner());
    if !peers.contains_key(&ip) && peers.len() >= MAX_PEER_BUCKETS {
        peers.retain(|_, stat| {
            stat.attempts.retain(|time| now.duration_since(*time) < Duration::from_secs(60));
            stat.live > 0 || !stat.attempts.is_empty()
        });
    }
    if !peers.contains_key(&ip) && peers.len() >= MAX_PEER_BUCKETS {
        return false;
    }
    let stat = peers.entry(ip).or_insert_with(|| PeerStat {
        live: 0,
        attempts: VecDeque::new(),
    });
    stat.attempts
        .retain(|time| now.duration_since(*time) < Duration::from_secs(60));
    // Record even attempts that fail a later admission test.
    stat.attempts.push_back(now);
    if stat.live >= PER_PEER_CONNECTION_LIMIT || stat.attempts.len() > PER_PEER_RATE_LIMIT {
        return false;
    }
    stat.live += 1;
    true
}

fn decrement_peer(inner: &Arc<ServerInner>, ip: IpAddr) {
    if let Some(stat) = inner
        .peers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_mut(&ip)
    {
        stat.live = stat.live.saturating_sub(1);
    }
}

fn make_server_connection(inner: &Arc<ServerInner>, stream: TcpStream, peer_ip: IpAddr) -> TResult<()> {
    let id = inner.next_id.fetch_add(1, Ordering::Relaxed);
    let temp_id = loop {
        let bytes = random_bytes(8).map_err(|e| TransportError::Io(e.to_string()))?;
        let candidate = bytes;
        let temporary_present = inner
            .temporary
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&candidate);
        let permanent_present = inner
            .permanent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&candidate);
        if !temporary_present && !permanent_present {
            break candidate;
        }
    };
    let weak = Arc::downgrade(inner);
    let temp_for_handshake = temp_id.clone();
    let handshake_connection_id = id;
    let handshake_callback: HandshakeCallback = Arc::new(move |temp| {
        if temp != temp_for_handshake {
            return;
        }
        if let Some(inner) = weak.upgrade() {
            let valid = inner
                .temporary
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&temp)
                .is_some_and(|conn| conn.id == handshake_connection_id && !conn.is_closed());
            if valid {
                let callback = Arc::clone(&inner.handshake_callback);
                let weak_again = Arc::downgrade(&inner);
                let temp_for_log = temp.clone();
                if let Err(error) = inner.handshake_pool.submit(Box::new(move || {
                    if let Some(inner) = weak_again.upgrade() {
                        let still_valid = inner
                            .temporary
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&temp)
                            .is_some_and(|conn| conn.id == handshake_connection_id && !conn.is_closed());
                        if still_valid {
                            callback(temp);
                        }
                    }
                })) {
                    eprintln!(
                        "network2: failed to schedule handshake callback for connection {} (temporary client id {}): {}",
                        handshake_connection_id, hex::encode(&temp_for_log), error
                    );
                    let conn = inner
                        .temporary
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&temp_for_log)
                        .cloned();
                    if let Some(conn) = conn {
                        conn.close();
                    }
                }
            }
        }
    });
    let weak = Arc::downgrade(inner);
    let exchange_connection_id = id;
    let exchange_callback: ServerExchangeCallback = Arc::new(move |cid, eid| {
        if let Some(inner) = weak.upgrade() {
            let valid = inner
                .connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&exchange_connection_id)
                .is_some_and(|conn| conn.is_eid_active(eid));
            if valid {
                let callback = Arc::clone(&inner.exchange_callback);
                let weak_again = Arc::downgrade(&inner);
                let client_id_for_log = hex::encode(&cid);
                if let Err(error) = inner.exchange_pool.submit(Box::new(move || {
                    if let Some(inner) = weak_again.upgrade() {
                        let still_valid = inner
                            .connections
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&exchange_connection_id)
                            .is_some_and(|conn| conn.is_eid_active(eid));
                        if still_valid {
                            callback(cid, eid);
                        } else {
                            eprintln!(
                                "network2: skipped exchange callback because connection {} or EID {} is no longer active",
                                exchange_connection_id, hex::encode(eid)
                            );
                        }
                    }
                })) {
                    eprintln!(
                        "network2: failed to schedule exchange callback for connection {} (client_id {}, EID {}): {}",
                        exchange_connection_id, client_id_for_log, hex::encode(eid), error
                    );
                    let conn = inner
                        .connections
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&exchange_connection_id)
                        .cloned();
                    if let Some(conn) = conn {
                        conn.close();
                    }
                }
            } else {
                eprintln!(
                    "network2: ignored exchange event for inactive connection {} (EID {})",
                    exchange_connection_id, hex::encode(eid)
                );
            }
        }
    });
    let weak = Arc::downgrade(inner);
    let close_callback: CloseCallback = Arc::new(move |connection_id, cid| {
        if let Some(inner) = weak.upgrade() {
            inner
                .connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&connection_id);
            inner
                .temporary
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|_, conn| conn.id != connection_id);
            inner
                .permanent
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|_, conn| conn.id != connection_id);
            decrement_peer(&inner, peer_ip);
            if let Some(cid) = cid {
                let callback = Arc::clone(&inner.disconnect_callback);
                let client_id_for_log = hex::encode(&cid);
                if let Err(error) = inner
                    .disconnect_pool
                    .submit(Box::new(move || callback(cid, connection_id)))
                {
                    eprintln!(
                        "network2: failed to schedule disconnect callback for connection {} (client_id {}): {}",
                        connection_id, client_id_for_log, error
                    );
                }
            }
        }
    });
    let reader = stream.try_clone()?;
    let writer = stream.try_clone()?;
    let conn = Connection::new(
        id,
        Some(temp_id.clone()),
        &stream,
        Arc::clone(&inner.global_memory),
        512 * 1024 * 1024,
        inner.magic1,
        inner.magic2,
        true,
        Some(handshake_callback),
        Some(exchange_callback),
        None,
        Some(close_callback),
    )?;
    inner
        .connections
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, Arc::clone(&conn));
    inner
        .temporary
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(temp_id, Arc::clone(&conn));
    conn.start(reader, writer);
    Ok(())
}

fn parse_eid(value: &[u8]) -> TResult<[u8; 8]> {
    if value.len() != 8 {
        return Err(TransportError::InvalidEid);
    }
    let mut eid = [0u8; 8];
    eid.copy_from_slice(value);
    Ok(eid)
}

#[derive(Clone)]
pub struct TransportClient {
    conn: Arc<Connection>,
}

impl TransportClient {
    pub fn connect(
        host: &str,
        port: u16,
        simult_exchanges: usize,
        callback: Arc<dyn Fn([u8; 8]) + Send + Sync>,
    ) -> TResult<Self> {
        if !(1..=64).contains(&simult_exchanges) {
            return Err(TransportError::Io("pool worker count must be 1 through 64".into()));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream_opt = None;
        for address in (host, port).to_socket_addrs()? {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if let Ok(stream) = TcpStream::connect_timeout(&address, remaining) {
                stream_opt = Some(stream);
                break;
            }
        }
        let mut stream = stream_opt.ok_or_else(|| TransportError::Io("connect timeout or refused".into()))?;
        let _ = stream.set_nodelay(true);
        {
            let socket = SockRef::from(&stream);
            let _ = socket.set_recv_buffer_size(64 * 1024);
            let _ = socket.set_send_buffer_size(64 * 1024);
            let _ = socket.set_keepalive(true);
        }
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut greeting = [0u8; 16];
        stream.read_exact(&mut greeting)?;
        stream.set_read_timeout(Some(READ_TICK))?;
        stream.set_write_timeout(Some(READ_TICK))?;
        let magic1: [u8; 8] = greeting[..8].try_into().expect("8-byte magic");
        let magic2: [u8; 8] = greeting[8..].try_into().expect("8-byte magic");
        if magic1 == magic2 {
            return Err(TransportError::Io("invalid server greeting".into()));
        }
        let pool = WorkerPool::new(simult_exchanges);
        let connection_slot: Arc<Mutex<Option<Weak<Connection>>>> = Arc::new(Mutex::new(None));
        let slot_for_callback = Arc::clone(&connection_slot);
        let on_client_exchange: ClientExchangeCallback = Arc::new(move |eid| {
            let callback = Arc::clone(&callback);
            let weak_connection = slot_for_callback
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let _ = pool.submit(Box::new(move || {
                if let Some(conn) = weak_connection.and_then(|weak| weak.upgrade()) {
                    if conn.is_eid_active(eid) {
                        callback(eid);
                    }
                }
            }));
        });
        let reader = stream.try_clone()?;
        let writer = stream.try_clone()?;
        let conn = Connection::new(
            1,
            None,
            &stream,
            Arc::new(AtomicUsize::new(0)),
            128 * 1024 * 1024,
            magic1,
            magic2,
            false,
            None,
            None,
            Some(on_client_exchange),
            None,
        )?;
        *connection_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::downgrade(&conn));
        conn.start(reader, writer);
        Ok(Self { conn })
    }

    pub fn magic1(&self) -> Vec<u8> {
        self.conn.magic1.to_vec()
    }

    pub fn magic2(&self) -> Vec<u8> {
        self.conn.magic2.to_vec()
    }

    pub fn send_handshake(&self, payload: Vec<u8>) -> TResult<()> {
        self.conn.queue_send(payload, None, false)?;
        Ok(())
    }

    pub fn recv_handshake(&self, timeout: Option<Duration>) -> TResult<Option<Vec<u8>>> {
        self.conn.recv(false, None, timeout)
    }

    pub fn auth_finished(&self) -> TResult<()> {
        self.conn.auth_finished(None)
    }

    pub fn send(&self, payload: Vec<u8>, eid: Option<Vec<u8>>) -> TResult<Vec<u8>> {
        let eid = eid.as_deref().map(parse_eid).transpose()?;
        Ok(self.conn.queue_send(payload, eid, true)?.to_vec())
    }

    pub fn recv(&self, eid: &[u8], timeout: Option<Duration>) -> TResult<Option<Vec<u8>>> {
        self.conn.recv(true, Some(parse_eid(eid)?), timeout)
    }

    pub fn is_authed(&self) -> bool {
        self.conn.is_authenticated() && !self.conn.is_closed()
    }

    pub fn set_backpressure(&self, enabled: bool) {
        self.conn.set_backpressure(enabled);
    }

    pub fn close(&self) {
        self.conn.close();
    }
}