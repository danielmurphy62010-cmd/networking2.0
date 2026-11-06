//! L3 protocol: persistent identity keys, all three handshakes, session AEAD,
//! exchange callbacks and TCPServer admin helper methods.

use crate::{crypto, transport};
use pyo3::{prelude::*, types::PyBytes};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use thiserror::Error;

const SERVER_DIR: &str = "server keys";
const AUTH_DIR: &str = "auth keys";
const CLIENT_DIR: &str = "client keys";
const SERVER_SALT_FILE: &str = "SERVER SALT";
const SERVER_SIGNING_FILE: &str = "SIGNING KEY";
const ADMIN_TOTP_FILE: &str = "ADMIN - TOTP";
const BOOTSTRAP_TOTP_FILE: &str = "BOOTSTRAP - TOTP";
const CLIENT_SALT_FILE: &str = "salt";
const CLIENT_AUTH_FILE: &str = "auth_key";
const CLIENT_SERVER_CERT_FILE: &str = "server_cert";
const MAX_TIMEOUT: Duration = Duration::from_secs(10);
// Preserve the protocol's original 1 s / 5 s defaults. The benchmark scripts
// may opt into longer windows because the Argon2id handshake KDF is expensive.
const HANDSHAKE_FIRST_TIMEOUT: Duration = Duration::from_secs(1);
const HANDSHAKE_DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const EXCHANGE_CALLBACK_TIMEOUT: Duration = Duration::from_secs(10);
const ADMIN_PREFIX: &[u8; 9] = b"REQ_ADMIN";

fn configured_timeout(env_name: &str, fallback: Duration) -> Duration {
    std::env::var(env_name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|millis| (1..=300_000).contains(millis))
        .map(Duration::from_millis)
        .unwrap_or(fallback)
}

fn handshake_first_timeout() -> Duration {
    configured_timeout("NETWORK2_HANDSHAKE_FIRST_TIMEOUT_MS", HANDSHAKE_FIRST_TIMEOUT)
}

fn handshake_default_timeout() -> Duration {
    configured_timeout("NETWORK2_HANDSHAKE_DEFAULT_TIMEOUT_MS", HANDSHAKE_DEFAULT_TIMEOUT)
}

fn exchange_callback_timeout() -> Duration {
    configured_timeout(
        "NETWORK2_EXCHANGE_CALLBACK_TIMEOUT_MS",
        EXCHANGE_CALLBACK_TIMEOUT,
    )
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct ProtocolFailure(pub String);

impl From<crypto::CryptoError> for ProtocolFailure {
    fn from(value: crypto::CryptoError) -> Self {
        Self(value.to_string())
    }
}
impl From<transport::TransportError> for ProtocolFailure {
    fn from(value: transport::TransportError) -> Self {
        Self(value.to_string())
    }
}
impl From<io::Error> for ProtocolFailure {
    fn from(value: io::Error) -> Self {
        Self(value.to_string())
    }
}

pub type PResult<T> = Result<T, ProtocolFailure>;


const ACK_EID: [u8; 8] = *b"N2ACK001";
const ACK_HELLO_MAGIC: &[u8; 8] = b"N2ACKH01";
const ACK_CHALLENGE_MAGIC: &[u8; 8] = b"N2ACKC01";
const ACK_FINISH_MAGIC: &[u8; 8] = b"N2ACKF01";
const ACK_HELLO_TAG: &[u8; 8] = b"HELLO1!!";
const ACK_CHALLENGE_TAG: &[u8; 8] = b"CHALNG1!";
const ACK_FINISH_TAG: &[u8; 8] = b"FINISH1!";
const ACK_READY_TAG: &[u8; 8] = b"READY1!!";
const MAX_DATA_RETRIES: usize = 10;
const ACK_COPIES: usize = 3;
const ACK_RETRY_BASE: Duration = Duration::from_millis(250);
const ACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// N is the handshake port. Ten bulk/ACK pairs occupy N+1 through N+20.
const PORT_PAIR_COUNT: usize = 10;
const PORT_PAIRS_PER_CLIENT: usize = 4;
const PORT_ASSIGNMENT_MAGIC: &[u8; 8] = b"N2PAIR01";
const PORT_ASSIGNMENT_AAD: &[u8] = b"network2-port-assignment-v1";

const DATA_HELLO_MAGIC: &[u8; 8] = b"N2DATAH1";
const DATA_CHALLENGE_MAGIC: &[u8; 8] = b"N2DATAC1";
const DATA_FINISH_MAGIC: &[u8; 8] = b"N2DATAF1";
const DATA_HELLO_TAG: &[u8; 8] = b"DHELLO1!";
const DATA_CHALLENGE_TAG: &[u8; 8] = b"DCHALN1!";
const DATA_FINISH_TAG: &[u8; 8] = b"DFINISH!";
const DATA_READY_MAGIC: &[u8; 8] = b"N2DATAR1";
const DATA_READY_TAG: &[u8; 8] = b"DREADY1!";

fn ack_control_key(session_key: &[u8]) -> Vec<u8> {
    crypto::basic_kdf(session_key, b"network2-ack-control-key-v1", 32)
}

fn ack_control_key_id(control_key: &[u8]) -> Vec<u8> {
    crypto::basic_kdf(control_key, b"network2-ack-control-key-id-v1", 16)
}

fn port_channel_key(
    control_key: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
    role: &[u8],
    pair_index: usize,
) -> Vec<u8> {
    let mut context = b"network2-port-channel-v1".to_vec();
    context.push(0);
    context.extend_from_slice(role);
    context.push(pair_index as u8);
    context.extend_from_slice(client_nonce);
    context.extend_from_slice(server_nonce);
    crypto::basic_kdf(control_key, &context, 32)
}

fn port_handshake_aad(
    role: &[u8],
    label: &[u8],
    pair_index: usize,
    key_id: &[u8],
) -> Vec<u8> {
    let mut aad = b"network2-port-handshake-v1".to_vec();
    aad.push(0);
    aad.extend_from_slice(role);
    aad.push(pair_index as u8);
    aad.extend_from_slice(label);
    aad.push(0);
    aad.extend_from_slice(key_id);
    aad
}

fn encode_port_assignment(key: &[u8], pairs: &[usize; PORT_PAIRS_PER_CLIENT]) -> PResult<Vec<u8>> {
    let mut plaintext = Vec::with_capacity(2 + PORT_PAIRS_PER_CLIENT);
    plaintext.push(1); // assignment format version
    plaintext.push(PORT_PAIRS_PER_CLIENT as u8);
    for pair in pairs {
        if *pair >= PORT_PAIR_COUNT {
            return Err(ProtocolFailure("invalid port-pair assignment".into()));
        }
        plaintext.push(*pair as u8);
    }
    let encrypted = crypto::encrypt_gcm(&plaintext, key, Some(PORT_ASSIGNMENT_AAD))?;
    let mut frame = PORT_ASSIGNMENT_MAGIC.to_vec();
    frame.extend_from_slice(&encrypted);
    Ok(frame)
}

fn decode_port_assignment(frame: &[u8], key: &[u8]) -> PResult<[usize; PORT_PAIRS_PER_CLIENT]> {
    if frame.len() < PORT_ASSIGNMENT_MAGIC.len() + crypto::AES_GCM_OVERHEAD
        || &frame[..PORT_ASSIGNMENT_MAGIC.len()] != PORT_ASSIGNMENT_MAGIC
    {
        return Err(ProtocolFailure("invalid port-pair assignment frame".into()));
    }
    let plaintext = crypto::decrypt_gcm(
        &frame[PORT_ASSIGNMENT_MAGIC.len()..],
        key,
        Some(PORT_ASSIGNMENT_AAD),
    )?;
    if plaintext.len() != 2 + PORT_PAIRS_PER_CLIENT
        || plaintext[0] != 1
        || plaintext[1] as usize != PORT_PAIRS_PER_CLIENT
    {
        return Err(ProtocolFailure("invalid port-pair assignment payload".into()));
    }
    let mut pairs = [0usize; PORT_PAIRS_PER_CLIENT];
    let mut seen = [false; PORT_PAIR_COUNT];
    for (slot, value) in pairs.iter_mut().zip(plaintext[2..].iter()) {
        let pair = *value as usize;
        if pair >= PORT_PAIR_COUNT || seen[pair] {
            return Err(ProtocolFailure("invalid or duplicate assigned port pair".into()));
        }
        seen[pair] = true;
        *slot = pair;
    }
    Ok(pairs)
}

fn eid_pair_slot(eid: &[u8; 8]) -> usize {
    (eid.iter().fold(0u8, |folded, byte| folded ^ byte) as usize)
        % PORT_PAIRS_PER_CLIENT
}

fn selected_pair(eid: &[u8; 8], assigned: &[usize; PORT_PAIRS_PER_CLIENT]) -> usize {
    assigned[eid_pair_slot(eid)]
}

fn ack_peer_cid(main_cid: &[u8], pair_index: usize) -> Vec<u8> {
    let mut context = b"network2-ack-transport-cid-v1".to_vec();
    context.push(pair_index as u8);
    crypto::basic_kdf(main_cid, &context, 32)
}

fn ack_record_aad(direction: u8, counter: u64) -> Vec<u8> {
    let mut aad = b"network2-ack-record-v1".to_vec();
    aad.push(direction);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad
}

fn ack_retry_timeout(retry: usize) -> Duration {
    ACK_RETRY_BASE * (1u32 << retry.min(3))
}

#[derive(Clone)]
enum AckTx {
    Server {
        transport: transport::TransportServer,
        peer_cid: Vec<u8>,
    },
    Client {
        transport: transport::TransportClient,
    },
}

impl AckTx {
    fn send(&self, payload: Vec<u8>) -> PResult<()> {
        match self {
            Self::Server { transport, peer_cid } => {
                transport.send(peer_cid, payload, Some(ACK_EID.to_vec()))?;
            }
            Self::Client { transport } => {
                transport.send(payload, Some(ACK_EID.to_vec()))?;
            }
        }
        Ok(())
    }
}

struct PendingAck {
    state: Mutex<Option<bool>>,
    changed: std::sync::Condvar,
}

impl PendingAck {
    fn new() -> Self {
        Self {
            state: Mutex::new(None),
            changed: std::sync::Condvar::new(),
        }
    }

    fn reset(&self) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn set(&self, acknowledged: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if *state != Some(true) {
            *state = Some(acknowledged);
        }
        self.changed.notify_all();
    }

    fn signal(&self) {
        self.changed.notify_all();
    }

    fn wait(&self, timeout: Duration, closed: &AtomicBool) -> Option<bool> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if state.is_some() {
                return *state;
            }
            if closed.load(Ordering::Acquire) {
                return None;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (next, result) = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|e| e.into_inner());
            state = next;
            if result.timed_out() && state.is_none() {
                return None;
            }
        }
    }
}

struct AckChannel {
    key: Vec<u8>,
    tx: AckTx,
    peer_cid: Vec<u8>,
    peer_connection_id: u64,
    send_direction: u8,
    receive_direction: u8,
    expected_data_direction: u8,
    send_counter: Mutex<u64>,
    receive_counter: Mutex<u64>,
    pending: Mutex<HashMap<u64, Arc<PendingAck>>>,
    closed: AtomicBool,
}

impl AckChannel {
    fn server(
        key: Vec<u8>,
        transport: transport::TransportServer,
        peer_cid: Vec<u8>,
        peer_connection_id: u64,
    ) -> Self {
        Self {
            key,
            tx: AckTx::Server {
                transport,
                peer_cid: peer_cid.clone(),
            },
            peer_cid,
            peer_connection_id,
            send_direction: b'1',
            receive_direction: b'0',
            expected_data_direction: b'1',
            send_counter: Mutex::new(0),
            receive_counter: Mutex::new(0),
            pending: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        }
    }

    fn client(key: Vec<u8>, transport: transport::TransportClient) -> Self {
        Self {
            key,
            tx: AckTx::Client { transport },
            peer_cid: Vec::new(),
            peer_connection_id: 0,
            send_direction: b'0',
            receive_direction: b'1',
            expected_data_direction: b'0',
            send_counter: Mutex::new(0),
            receive_counter: Mutex::new(1),
            pending: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        }
    }

    fn send_ready(&self) -> PResult<()> {
        let control_counter = {
            let mut counter = self.send_counter.lock().unwrap_or_else(|e| e.into_inner());
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| ProtocolFailure("ACK control counter exhausted".into()))?;
            *counter
        };
        let aad = ack_record_aad(self.send_direction, control_counter);
        let encrypted = crypto::encrypt_gcm(ACK_READY_TAG, &self.key, Some(&aad))?;
        let mut wire = Vec::with_capacity(8 + encrypted.len());
        wire.extend_from_slice(&control_counter.to_be_bytes());
        wire.extend_from_slice(&encrypted);
        self.tx.send(wire)
    }

    fn register_pending(&self, counter: u64) -> PResult<Arc<PendingAck>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(ProtocolFailure("ACK channel is closed".into()));
        }
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.contains_key(&counter) {
            return Err(ProtocolFailure("duplicate pending data counter".into()));
        }
        let waiter = Arc::new(PendingAck::new());
        pending.insert(counter, waiter.clone());
        Ok(waiter)
    }

    fn remove_pending(&self, counter: u64) {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&counter);
    }

    fn send_status(&self, acknowledged: bool, data_direction: u8, data_counter: u64) -> PResult<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(ProtocolFailure("ACK channel is closed".into()));
        }

        // TCP already retries lost segments. These independently authenticated
        // copies also cover a control frame discarded by the framing parser.
        // Each copy gets a fresh control counter/nonce; duplicate statuses are
        // idempotent at the sender because they name the same data counter.
        let copies = if acknowledged { ACK_COPIES } else { 1 };
        let mut queued = 0usize;
        let mut last_error = None;

        for _ in 0..copies {
            let control_counter = {
                let mut counter = self.send_counter.lock().unwrap_or_else(|e| e.into_inner());
                *counter = counter
                    .checked_add(1)
                    .ok_or_else(|| ProtocolFailure("ACK control counter exhausted".into()))?;
                *counter
            };
            let mut plaintext = Vec::with_capacity(10);
            plaintext.push(if acknowledged { 1 } else { 2 });
            plaintext.push(data_direction);
            plaintext.extend_from_slice(&data_counter.to_be_bytes());
            let aad = ack_record_aad(self.send_direction, control_counter);
            let encrypted = crypto::encrypt_gcm(&plaintext, &self.key, Some(&aad))?;
            let mut wire = Vec::with_capacity(8 + encrypted.len());
            wire.extend_from_slice(&control_counter.to_be_bytes());
            wire.extend_from_slice(&encrypted);

            match self.tx.send(wire) {
                Ok(()) => queued += 1,
                Err(error) => last_error = Some(error),
            }
        }

        if queued > 0 {
            Ok(())
        } else {
            Err(last_error.unwrap_or_else(|| {
                ProtocolFailure("could not enqueue ACK control record".into())
            }))
        }
    }

    fn receive_status(&self, wire: &[u8]) -> PResult<()> {
        if wire.len() < 8 + crypto::AES_GCM_OVERHEAD + 10 {
            return Err(ProtocolFailure("ACK control record is too short".into()));
        }
        let control_counter = u64::from_be_bytes(
            wire[..8].try_into().expect("eight-byte ACK counter"),
        );
        let aad = ack_record_aad(self.receive_direction, control_counter);
        let plaintext = crypto::decrypt_gcm(&wire[8..], &self.key, Some(&aad))?;
        if plaintext.len() != 10 || (plaintext[0] != 1 && plaintext[0] != 2) {
            return Err(ProtocolFailure("invalid ACK control payload".into()));
        }
        if plaintext[1] != self.expected_data_direction {
            return Err(ProtocolFailure("ACK control direction mismatch".into()));
        }

        let mut last = self.receive_counter.lock().unwrap_or_else(|e| e.into_inner());
        // Replayed control records are ignored after authenticating them.
        if control_counter <= *last {
            return Ok(());
        }
        *last = control_counter;
        drop(last);

        let data_counter = u64::from_be_bytes(
            plaintext[2..10].try_into().expect("eight-byte data counter"),
        );
        let waiter = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&data_counter)
            .cloned();
        if let Some(waiter) = waiter {
            waiter.set(plaintext[0] == 1);
        }
        Ok(())
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            for waiter in pending.values() {
                waiter.signal();
            }
        }
    }
}

fn send_data_with_ack<F>(
    channel: &Arc<AckChannel>,
    data_counter: u64,
    mut send_frame: F,
) -> PResult<()>
where
    F: FnMut() -> PResult<()>,
{
    let waiter = channel.register_pending(data_counter)?;
    let result = (|| {
        for retry in 0..=MAX_DATA_RETRIES {
            if channel.closed.load(Ordering::Acquire) {
                return Err(ProtocolFailure("ACK channel closed during send".into()));
            }
            waiter.reset();
            if let Err(error) = send_frame() {
                if retry == MAX_DATA_RETRIES {
                    return Err(error);
                }
                thread::sleep(ack_retry_timeout(retry));
                continue;
            }
            if waiter.wait(ack_retry_timeout(retry), &channel.closed) == Some(true) {
                return Ok(());
            }
        }
        Err(ProtocolFailure(format!(
            "data counter {data_counter} was not acknowledged after {} retries",
            MAX_DATA_RETRIES
        )))
    })();
    channel.remove_pending(data_counter);
    result
}

enum ReceivedData {
    Fresh {
        counter: u64,
        plaintext: Vec<u8>,
        fingerprint: [u8; 32],
    },
    Duplicate { counter: u64 },
    Rejected { counter: u64 },
}

fn decode_data_record(
    session: &mut Session,
    wire: &[u8],
    exchange: &[u8; 8],
    direction: u8,
) -> PResult<ReceivedData> {
    if wire.len() < 8 {
        return Err(ProtocolFailure("encrypted message is too short".into()));
    }
    let counter = u64::from_be_bytes(wire[..8].try_into().expect("eight-byte data counter"));
    if wire.len() < 8 + crypto::AES_GCM_OVERHEAD {
        return Ok(ReceivedData::Rejected { counter });
    }
    let mut aad = Vec::with_capacity(17);
    aad.extend_from_slice(exchange);
    aad.extend_from_slice(&wire[..8]);
    aad.push(direction);
    let plaintext = match crypto::decrypt_gcm(&wire[8..], &session.key, Some(&aad)) {
        Ok(value) => value,
        Err(_) => return Ok(ReceivedData::Rejected { counter }),
    };
    let fingerprint = *blake3::hash(wire).as_bytes();
    if counter == session.receive_counter && session.last_received_hash == Some(fingerprint) {
        return Ok(ReceivedData::Duplicate { counter });
    }
    if counter <= session.receive_counter {
        return Ok(ReceivedData::Rejected { counter });
    }
    Ok(ReceivedData::Fresh {
        counter,
        plaintext,
        fingerprint,
    })
}

fn spawn_server_ack_reader(
    transport: transport::TransportServer,
    peer_cid: Vec<u8>,
    channel: Arc<AckChannel>,
) -> PResult<()> {
    thread::Builder::new()
        .name("network2-ack-rx-server".into())
        .spawn(move || {
            loop {
                if channel.closed.load(Ordering::Acquire) {
                    break;
                }
                match transport.recv(&peer_cid, &ACK_EID, None) {
                    Ok(Some(wire)) => {
                        if let Err(error) = channel.receive_status(&wire) {
                            eprintln!("network2: rejected ACK control record: {error}");
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!("network2: ACK control receive failed: {error}");
                        break;
                    }
                }
            }
            channel.close();
        })
        .map(|_| ())
        .map_err(|error| ProtocolFailure(format!("could not start ACK reader: {error}")))
}

fn spawn_client_ack_reader(
    transport: transport::TransportClient,
    channel: Arc<AckChannel>,
) -> PResult<()> {
    thread::Builder::new()
        .name("network2-ack-rx-client".into())
        .spawn(move || {
            loop {
                if channel.closed.load(Ordering::Acquire) {
                    break;
                }
                match transport.recv(&ACK_EID, None) {
                    Ok(Some(wire)) => {
                        if let Err(error) = channel.receive_status(&wire) {
                            eprintln!("network2: rejected ACK control record: {error}");
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!("network2: ACK control receive failed: {error}");
                        break;
                    }
                }
            }
            channel.close();
        })
        .map(|_| ())
        .map_err(|error| ProtocolFailure(format!("could not start ACK reader: {error}")))
}

struct Session {
    key: Vec<u8>,
    send_counter: u64,
    receive_counter: u64,
    last_received_hash: Option<[u8; 32]>,
    send_gate: Arc<Mutex<()>>,
    admin: bool,
    username: Option<String>,
    connection_id: u64,
}

struct ServerStorage {
    at_rest_key: Vec<u8>,
    signing_private: Vec<u8>,
    signing_public: Vec<u8>,
    admin_totp: Vec<u8>,
    bootstrap_totp: Option<Vec<u8>>,
}

struct ClientIdentity {
    salt: Vec<u8>,
    at_rest_key: Vec<u8>,
    signing_private: Vec<u8>,
    signing_public: Vec<u8>,
    server_cert: Option<Vec<u8>>,
    bootstrap_code: Option<String>,
}

pub struct ProtocolServer {
    // Port N is retained only for the authenticated handshake/control lifetime.
    transport: Mutex<Option<transport::TransportServer>>,
    data_transports: Mutex<Vec<transport::TransportServer>>,
    ack_transports: Mutex<Vec<transport::TransportServer>>,
    assigned_pairs: Mutex<HashMap<Vec<u8>, [usize; PORT_PAIRS_PER_CLIENT]>>,
    next_pair: AtomicUsize,
    ack_channels: Mutex<HashMap<(Vec<u8>, usize), Arc<AckChannel>>>,
    signing_private: Vec<u8>,
    signing_public: Vec<u8>,
    at_rest_key: Vec<u8>,
    admin_totp: Vec<u8>,
    bootstrap_totp: Mutex<Option<Vec<u8>>>,
    pending_bootstrap_totp: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    enable_bootstrap: AtomicBool,
    last_bootstrap: Mutex<Option<Instant>>,
    last_admin: Mutex<Option<Instant>>,
    sessions: Mutex<HashMap<Vec<u8>, Arc<Mutex<Session>>>>,
    callback: Option<Py<PyAny>>,
    python_self: Mutex<Option<Py<PyAny>>>,
    closed: AtomicBool,
}

impl ProtocolServer {
    pub fn new(
        host: String,
        port: u16,
        password: String,
        new_totp: bool,
        callback: Option<Py<PyAny>>,
        simult_exchanges: usize,
        _requested_ack_port: Option<u16>,
    ) -> PResult<Arc<Self>> {
        if !(1..=64).contains(&simult_exchanges) {
            return Err(ProtocolFailure("simult_exchanges must be between 1 and 64".into()));
        }
        if port == 0 || port.checked_add((PORT_PAIR_COUNT * 2) as u16).is_none() {
            return Err(ProtocolFailure(
                "base port must be between 1 and 65515 so all 21 ports fit".into(),
            ));
        }
        let storage = initialize_server_storage(&password, new_totp)?;
        let server = Arc::new(Self {
            transport: Mutex::new(None),
            data_transports: Mutex::new(Vec::with_capacity(PORT_PAIR_COUNT)),
            ack_transports: Mutex::new(Vec::with_capacity(PORT_PAIR_COUNT)),
            assigned_pairs: Mutex::new(HashMap::new()),
            next_pair: AtomicUsize::new(0),
            ack_channels: Mutex::new(HashMap::new()),
            signing_private: storage.signing_private,
            signing_public: storage.signing_public,
            at_rest_key: storage.at_rest_key,
            admin_totp: storage.admin_totp,
            bootstrap_totp: Mutex::new(storage.bootstrap_totp),
            pending_bootstrap_totp: Mutex::new(HashMap::new()),
            enable_bootstrap: AtomicBool::new(false),
            last_bootstrap: Mutex::new(None),
            last_admin: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
            callback,
            python_self: Mutex::new(None),
            closed: AtomicBool::new(false),
        });

        let weak = Arc::downgrade(&server);
        let handshake = Arc::new(move |temp: Vec<u8>| {
            if let Some(server) = weak.upgrade() {
                server.run_handshake(&temp);
            }
        });
        // Port N is the handshake/control channel; exchanges are only accepted
        // on the assigned bulk ports below.
        let exchange = Arc::new(|_cid: Vec<u8>, _eid: [u8; 8]| {});
        let weak = Arc::downgrade(&server);
        let disconnected = Arc::new(move |cid: Vec<u8>, connection_id: u64| {
            if let Some(server) = weak.upgrade() {
                server.forget_client_generation(&cid, connection_id);
            }
        });
        let transport = transport::TransportServer::new(
            host.clone(),
            port,
            1,
            simult_exchanges,
            handshake,
            exchange,
            disconnected,
        )?;

        let mut data_transports = Vec::with_capacity(PORT_PAIR_COUNT);
        let mut ack_transports = Vec::with_capacity(PORT_PAIR_COUNT);
        for pair_index in 0..PORT_PAIR_COUNT {
            let data_port = port + 1 + (pair_index as u16 * 2);
            let ack_port = data_port + 1;

            let weak = Arc::downgrade(&server);
            let data_handshake = Arc::new(move |temp: Vec<u8>| {
                if let Some(server) = weak.upgrade() {
                    server.run_data_handshake(pair_index, &temp);
                }
            });
            let weak = Arc::downgrade(&server);
            let data_exchange = Arc::new(move |cid: Vec<u8>, eid: [u8; 8]| {
                if let Some(server) = weak.upgrade() {
                    if server.pair_for_eid(&cid, &eid) == Some(pair_index) {
                        server.dispatch_exchange(cid, eid);
                    } else if let Ok(transport) = server.data_transport(pair_index) {
                        let _ = transport.close_client(&cid);
                    }
                }
            });
            let data_disconnected = Arc::new(|_cid: Vec<u8>, _connection_id: u64| {});
            data_transports.push(transport::TransportServer::new(
                host.clone(),
                data_port,
                1,
                simult_exchanges,
                data_handshake,
                data_exchange,
                data_disconnected,
            )?);

            let weak = Arc::downgrade(&server);
            let ack_handshake = Arc::new(move |temp: Vec<u8>| {
                if let Some(server) = weak.upgrade() {
                    server.run_ack_handshake(pair_index, &temp);
                }
            });
            let ack_exchange = Arc::new(|_cid: Vec<u8>, _eid: [u8; 8]| {});
            let weak = Arc::downgrade(&server);
            let ack_disconnected = Arc::new(move |cid: Vec<u8>, connection_id: u64| {
                if let Some(server) = weak.upgrade() {
                    server.forget_ack_generation(pair_index, &cid, connection_id);
                }
            });
            ack_transports.push(transport::TransportServer::new(
                host.clone(),
                ack_port,
                1,
                simult_exchanges,
                ack_handshake,
                ack_exchange,
                ack_disconnected,
            )?);
        }

        *server.transport.lock().unwrap_or_else(|e| e.into_inner()) = Some(transport.clone());
        *server.data_transports.lock().unwrap_or_else(|e| e.into_inner()) = data_transports.clone();
        *server.ack_transports.lock().unwrap_or_else(|e| e.into_inner()) = ack_transports.clone();

        let mut started = Vec::with_capacity(1 + PORT_PAIR_COUNT * 2);
        if let Err(error) = transport.start() {
            return Err(error.into());
        }
        started.push(transport);
        for pair_index in 0..PORT_PAIR_COUNT {
            for listener in [&data_transports[pair_index], &ack_transports[pair_index]] {
                if let Err(error) = listener.start() {
                    for running in started {
                        running.stop();
                    }
                    return Err(error.into());
                }
                started.push(listener.clone());
            }
        }

        print_server_identity(&server.signing_public);
        Ok(server)
    }

    pub fn set_python_self(&self, object: Py<PyAny>) {
        // Store a weakref: the Python wrapper owns this Arc, so retaining a
        // strong reference here would create a wrapper <-> protocol cycle.
        let weak = Python::attach(|py| -> PyResult<Py<PyAny>> {
            Ok(py
                .import("weakref")?
                .getattr("ref")?
                .call1((object.bind(py),))?
                .unbind())
        })
        .expect("network2 wrapper must support weak references");
        *self.python_self.lock().unwrap_or_else(|e| e.into_inner()) = Some(weak);
    }

    fn transport(&self) -> PResult<transport::TransportServer> {
        self.transport
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
            .ok_or_else(|| ProtocolFailure("server transport is not running".into()))
    }

    fn data_transport(&self, pair_index: usize) -> PResult<transport::TransportServer> {
        self.data_transports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(pair_index)
            .cloned()
            .ok_or_else(|| ProtocolFailure("bulk transport pair is unavailable".into()))
    }

    fn ack_transport(&self, pair_index: usize) -> PResult<transport::TransportServer> {
        self.ack_transports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(pair_index)
            .cloned()
            .ok_or_else(|| ProtocolFailure("ACK transport pair is unavailable".into()))
    }

    fn ack_channel(&self, cid: &[u8], pair_index: usize) -> PResult<Arc<AckChannel>> {
        self.ack_channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(cid.to_vec(), pair_index))
            .cloned()
            .ok_or_else(|| ProtocolFailure("ACK channel for the selected port pair is not connected".into()))
    }

    fn assigned_pairs(&self, cid: &[u8]) -> Option<[usize; PORT_PAIRS_PER_CLIENT]> {
        self.assigned_pairs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(cid)
            .copied()
    }

    fn pair_for_eid(&self, cid: &[u8], eid: &[u8; 8]) -> Option<usize> {
        self.assigned_pairs(cid).map(|pairs| selected_pair(eid, &pairs))
    }

    fn pair_is_assigned(&self, cid: &[u8], pair_index: usize) -> bool {
        self.assigned_pairs(cid)
            .is_some_and(|pairs| pairs.contains(&pair_index))
    }

    fn allocate_pairs(&self) -> [usize; PORT_PAIRS_PER_CLIENT] {
        let start = self.next_pair.fetch_add(1, Ordering::Relaxed) % PORT_PAIR_COUNT;
        std::array::from_fn(|slot| (start + slot) % PORT_PAIR_COUNT)
    }

    fn find_session_by_ack_key_id(&self, key_id: &[u8]) -> PResult<(Vec<u8>, Vec<u8>)> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        for (cid, session) in sessions.iter() {
            let session = session.lock().unwrap_or_else(|e| e.into_inner());
            let control_key = ack_control_key(&session.key);
            let candidate = ack_control_key_id(&control_key);
            if ct_equal(&candidate, key_id) {
                return Ok((cid.clone(), control_key));
            }
        }
        Err(ProtocolFailure("secondary channel authentication failed".into()))
    }

    fn run_data_handshake(self: &Arc<Self>, pair_index: usize, temp_cid: &[u8]) {
        if let Err(error) = self.data_handshake(pair_index, temp_cid) {
            eprintln!("network2 bulk-channel handshake failed on pair {pair_index}: {error}");
            if let Ok(transport) = self.data_transport(pair_index) {
                transport.close_handshake(temp_cid);
            }
        }
    }

    fn data_handshake(self: &Arc<Self>, pair_index: usize, temp_cid: &[u8]) -> PResult<()> {
        let transport = self.data_transport(pair_index)?;
        let hello = transport
            .recv_handshake(temp_cid, Some(ACK_CONNECT_TIMEOUT))?
            .ok_or_else(|| ProtocolFailure("bulk-channel hello timed out".into()))?;
        if hello.len() < DATA_HELLO_MAGIC.len() + 16 + 8 + crypto::AES_GCM_OVERHEAD
            || &hello[..DATA_HELLO_MAGIC.len()] != DATA_HELLO_MAGIC
        {
            return Err(ProtocolFailure("invalid bulk-channel hello".into()));
        }

        let key_id = &hello[DATA_HELLO_MAGIC.len()..DATA_HELLO_MAGIC.len() + 16];
        let encrypted = &hello[DATA_HELLO_MAGIC.len() + 16..];
        let (main_cid, control_key) = self.find_session_by_ack_key_id(key_id)?;
        if !self.pair_is_assigned(&main_cid, pair_index) {
            return Err(ProtocolFailure("bulk port pair is not assigned to this client".into()));
        }
        let hello_aad = port_handshake_aad(b"data", b"client-hello", pair_index, key_id);
        let hello_plain = crypto::decrypt_gcm(encrypted, &control_key, Some(&hello_aad))?;
        if hello_plain.len() != 40 || !ct_equal(&hello_plain[..8], DATA_HELLO_TAG) {
            return Err(ProtocolFailure("bulk-channel hello proof failed".into()));
        }
        let client_nonce = &hello_plain[8..40];
        let server_nonce = crypto::random_bytes(32)?;

        let mut challenge_plain = Vec::with_capacity(72);
        challenge_plain.extend_from_slice(DATA_CHALLENGE_TAG);
        challenge_plain.extend_from_slice(client_nonce);
        challenge_plain.extend_from_slice(&server_nonce);
        let challenge_aad = port_handshake_aad(b"data", b"server-challenge", pair_index, key_id);
        let challenge_encrypted =
            crypto::encrypt_gcm(&challenge_plain, &control_key, Some(&challenge_aad))?;
        let mut challenge = DATA_CHALLENGE_MAGIC.to_vec();
        challenge.extend_from_slice(&challenge_encrypted);
        transport.send_handshake(temp_cid, challenge)?;

        let finish = transport
            .recv_handshake(temp_cid, Some(ACK_CONNECT_TIMEOUT))?
            .ok_or_else(|| ProtocolFailure("bulk-channel finish timed out".into()))?;
        if finish.len() < DATA_FINISH_MAGIC.len() + 8 + crypto::AES_GCM_OVERHEAD
            || &finish[..DATA_FINISH_MAGIC.len()] != DATA_FINISH_MAGIC
        {
            return Err(ProtocolFailure("invalid bulk-channel finish".into()));
        }
        let finish_aad = port_handshake_aad(b"data", b"client-finish", pair_index, key_id);
        let finish_plain = crypto::decrypt_gcm(
            &finish[DATA_FINISH_MAGIC.len()..],
            &control_key,
            Some(&finish_aad),
        )?;
        let mut expected_finish = Vec::with_capacity(72);
        expected_finish.extend_from_slice(DATA_FINISH_TAG);
        expected_finish.extend_from_slice(client_nonce);
        expected_finish.extend_from_slice(&server_nonce);
        if !ct_equal(&finish_plain, &expected_finish) {
            return Err(ProtocolFailure("bulk-channel finish proof failed".into()));
        }

        let channel_key = port_channel_key(
            &control_key, client_nonce, &server_nonce, b"data", pair_index,
        );
        let ready_aad = port_handshake_aad(b"data", b"server-ready", pair_index, key_id);
        let mut ready_plain = DATA_READY_TAG.to_vec();
        ready_plain.push(pair_index as u8);
        let ready_encrypted = crypto::encrypt_gcm(&ready_plain, &channel_key, Some(&ready_aad))?;
        let mut ready = DATA_READY_MAGIC.to_vec();
        ready.extend_from_slice(&ready_encrypted);
        transport.send_handshake(temp_cid, ready)?;
        transport.auth_finished(temp_cid, main_cid, None)?;
        Ok(())
    }

    fn run_ack_handshake(self: &Arc<Self>, pair_index: usize, temp_cid: &[u8]) {
        if let Err(error) = self.ack_handshake(pair_index, temp_cid) {
            eprintln!("network2 ACK-channel handshake failed on pair {pair_index}: {error}");
            if let Ok(transport) = self.ack_transport(pair_index) {
                transport.close_handshake(temp_cid);
            }
        }
    }

    fn ack_handshake(self: &Arc<Self>, pair_index: usize, temp_cid: &[u8]) -> PResult<()> {
        let transport = self.ack_transport(pair_index)?;
        let hello = transport
            .recv_handshake(temp_cid, Some(ACK_CONNECT_TIMEOUT))?
            .ok_or_else(|| ProtocolFailure("ACK-channel hello timed out".into()))?;
        if hello.len() < ACK_HELLO_MAGIC.len() + 16 + 8 + crypto::AES_GCM_OVERHEAD
            || &hello[..ACK_HELLO_MAGIC.len()] != ACK_HELLO_MAGIC
        {
            return Err(ProtocolFailure("invalid ACK-channel hello".into()));
        }

        let key_id = &hello[ACK_HELLO_MAGIC.len()..ACK_HELLO_MAGIC.len() + 16];
        let encrypted = &hello[ACK_HELLO_MAGIC.len() + 16..];
        let (main_cid, control_key) = self.find_session_by_ack_key_id(key_id)?;
        if !self.pair_is_assigned(&main_cid, pair_index) {
            return Err(ProtocolFailure("ACK port pair is not assigned to this client".into()));
        }
        let hello_aad = port_handshake_aad(b"ack", b"client-hello", pair_index, key_id);
        let hello_plain = crypto::decrypt_gcm(encrypted, &control_key, Some(&hello_aad))?;
        if hello_plain.len() != 40 || !ct_equal(&hello_plain[..8], ACK_HELLO_TAG) {
            return Err(ProtocolFailure("ACK-channel hello proof failed".into()));
        }
        let client_nonce = &hello_plain[8..40];
        let server_nonce = crypto::random_bytes(32)?;

        let mut challenge_plain = Vec::with_capacity(72);
        challenge_plain.extend_from_slice(ACK_CHALLENGE_TAG);
        challenge_plain.extend_from_slice(client_nonce);
        challenge_plain.extend_from_slice(&server_nonce);
        let challenge_aad = port_handshake_aad(b"ack", b"server-challenge", pair_index, key_id);
        let challenge_encrypted =
            crypto::encrypt_gcm(&challenge_plain, &control_key, Some(&challenge_aad))?;
        let mut challenge = ACK_CHALLENGE_MAGIC.to_vec();
        challenge.extend_from_slice(&challenge_encrypted);
        transport.send_handshake(temp_cid, challenge)?;

        let finish = transport
            .recv_handshake(temp_cid, Some(ACK_CONNECT_TIMEOUT))?
            .ok_or_else(|| ProtocolFailure("ACK-channel finish timed out".into()))?;
        if finish.len() < ACK_FINISH_MAGIC.len() + 8 + crypto::AES_GCM_OVERHEAD
            || &finish[..ACK_FINISH_MAGIC.len()] != ACK_FINISH_MAGIC
        {
            return Err(ProtocolFailure("invalid ACK-channel finish".into()));
        }
        let finish_aad = port_handshake_aad(b"ack", b"client-finish", pair_index, key_id);
        let finish_plain =
            crypto::decrypt_gcm(&finish[ACK_FINISH_MAGIC.len()..], &control_key, Some(&finish_aad))?;
        let mut expected_finish = Vec::with_capacity(72);
        expected_finish.extend_from_slice(ACK_FINISH_TAG);
        expected_finish.extend_from_slice(client_nonce);
        expected_finish.extend_from_slice(&server_nonce);
        if !ct_equal(&finish_plain, &expected_finish) {
            return Err(ProtocolFailure("ACK-channel finish proof failed".into()));
        }

        let channel_key = port_channel_key(
            &control_key, client_nonce, &server_nonce, b"ack", pair_index,
        );
        let peer_cid = ack_peer_cid(&main_cid, pair_index);
        let peer_connection_id = transport.connection_id(temp_cid)?;
        self.close_ack_channel_for_pair(&main_cid, pair_index);
        transport.auth_finished(temp_cid, peer_cid.clone(), None)?;

        let channel = Arc::new(AckChannel::server(
            channel_key,
            transport.clone(),
            peer_cid.clone(),
            peer_connection_id,
        ));
        self.ack_channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((main_cid.clone(), pair_index), channel.clone());
        if let Err(error) =
            spawn_server_ack_reader(transport.clone(), peer_cid.clone(), channel.clone())
        {
            self.close_ack_channel_for_pair(&main_cid, pair_index);
            return Err(error);
        }
        if let Err(error) = channel.send_ready() {
            self.close_ack_channel_for_pair(&main_cid, pair_index);
            return Err(error);
        }
        Ok(())
    }

    fn close_ack_channel_for_pair(&self, main_cid: &[u8], pair_index: usize) {
        let channel = self
            .ack_channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(main_cid.to_vec(), pair_index));
        if let Some(channel) = channel {
            channel.close();
            if let Ok(transport) = self.ack_transport(pair_index) {
                let _ = transport.close_client(&channel.peer_cid);
            }
        }
    }

    fn close_ack_channels(&self, main_cid: &[u8]) {
        for pair_index in 0..PORT_PAIR_COUNT {
            self.close_ack_channel_for_pair(main_cid, pair_index);
        }
    }

    fn forget_ack_generation(&self, pair_index: usize, peer_cid: &[u8], connection_id: u64) {
        let main_cid = {
            let channels = self.ack_channels.lock().unwrap_or_else(|e| e.into_inner());
            channels.iter().find_map(|((main_cid, pair), channel)| {
                (*pair == pair_index
                    && channel.peer_cid == peer_cid
                    && channel.peer_connection_id == connection_id)
                    .then_some(main_cid.clone())
            })
        };
        if let Some(main_cid) = main_cid {
            self.close_ack_channel_for_pair(&main_cid, pair_index);
        }
    }

    pub fn magic1(&self) -> PResult<Vec<u8>> {
        Ok(self.transport()?.magic1())
    }

    pub fn magic2(&self) -> PResult<Vec<u8>> {
        Ok(self.transport()?.magic2())
    }

    pub fn set_bootstrap_enabled_internal(&self, enabled: bool) {
        // Assignment through the compatibility attribute is intentionally
        // permissive; the RPC method below enforces TOTP configuration.
        let can_enable = !enabled
            || self
                .bootstrap_totp
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some();
        if can_enable {
            self.enable_bootstrap.store(enabled, Ordering::Release);
        }
    }

    pub fn signing_keys(&self) -> (Vec<u8>, Vec<u8>) {
        (self.signing_private.clone(), self.signing_public.clone())
    }

    pub fn is_bootstrap_enabled(&self) -> bool {
        self.enable_bootstrap.load(Ordering::Acquire)
    }

    pub fn last_bootstrap_seconds(&self) -> Option<f64> {
        self.last_bootstrap
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|instant| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64()
                    - instant.elapsed().as_secs_f64()
            })
    }

    pub fn last_admin_seconds(&self) -> Option<f64> {
        self.last_admin
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|instant| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64()
                    - instant.elapsed().as_secs_f64()
            })
    }

    fn run_handshake(self: &Arc<Self>, temp_cid: &[u8]) {
        let result = self.handshake(temp_cid);
        if let Err(error) = result {
            eprintln!("network2 handshake failed: {error}");
            if let Ok(transport) = self.transport() {
                transport.close_handshake(temp_cid);
            }
        }
    }

    fn handshake(self: &Arc<Self>, temp_cid: &[u8]) -> PResult<()> {
        let transport = self.transport()?;
        let first = recv_handshake_required(
            &transport,
            temp_cid,
            handshake_first_timeout(),
            "initial client handshake frame",
        )?;
        transport.send_handshake(temp_cid, self.signing_public.clone())?;

        if first.starts_with(ADMIN_PREFIX) {
            if first.len() != ADMIN_PREFIX.len() + 57 {
                return Err(ProtocolFailure("malformed admin handshake prefix".into()));
            }
            return self.handshake_admin(temp_cid, &first[ADMIN_PREFIX.len()..]);
        }

        crypto::parse_framed_key(
            &first,
            Some(crypto::KeyKind::Ed448),
            Some(false),
        )?;
        let known = self.find_authorized_client(&first)?;
        if let Some(username) = known {
            self.handshake_known_client(temp_cid, &first, &username)
        } else {
            self.handshake_bootstrap(temp_cid, &first)
        }
    }

    fn find_authorized_client(&self, presented_public: &[u8]) -> PResult<Option<String>> {
        let entries = fs::read_dir(AUTH_DIR)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Ok(blob) = fs::read(&path) else { continue };
            // A damaged/revoked entry must not prevent other clients logging in.
            let Ok(public) = crypto::ed25519_verify(&self.signing_public, &blob) else {
                continue;
            };
            if public.len() == presented_public.len()
                && bool::from(public.as_slice().ct_eq(presented_public))
            {
                let name = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default()
                    .to_string();
                return Ok(Some(name));
            }
        }
        Ok(None)
    }

    fn handshake_known_client(
        self: &Arc<Self>,
        temp_cid: &[u8],
        client_public: &[u8],
        username: &str,
    ) -> PResult<()> {
        let transport = self.transport()?;
        transport.send_handshake(temp_cid, b"ACK".to_vec())?;
        let (server_ephemeral_private, server_ephemeral_public) =
            crypto::generate_keypair(crypto::KeyKind::X448)?;
        let server_signed = crypto::ed25519_sign(&self.signing_private, &server_ephemeral_public)?;
        transport.send_handshake(temp_cid, server_signed)?;
        let client_signed = recv_handshake_required(
            &transport,
            temp_cid,
            handshake_default_timeout(),
            "client signed ephemeral key",
        )?;
        let client_ephemeral_public = crypto::ed25519_verify(client_public, &client_signed)?;
        crypto::parse_framed_key(
            &client_ephemeral_public,
            Some(crypto::KeyKind::X448),
            Some(false),
        )?;
        let key = crypto::shared_secret(&server_ephemeral_private, &client_ephemeral_public)?;
        let cid = crypto::basic_kdf(client_public, &[], 6);
        let connection_id = transport.connection_id(temp_cid)?;
        self.register_session(
            temp_cid,
            cid,
            Session {
                key,
                send_counter: 1,
                receive_counter: 0,
                admin: false,
                username: Some(username.to_string()),
                connection_id,
                last_received_hash: None,
                send_gate: Arc::new(Mutex::new(())),
            },
        )
    }

    fn handshake_bootstrap(
        self: &Arc<Self>,
        temp_cid: &[u8],
        client_public: &[u8],
    ) -> PResult<()> {
        if !self.enable_bootstrap.load(Ordering::Acquire) {
            return Err(ProtocolFailure("bootstrap is disabled".into()));
        }
        let bootstrap_secret = self
            .bootstrap_totp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| ProtocolFailure("bootstrap TOTP is not configured".into()))?;
        {
            let mut last = self.last_bootstrap.lock().unwrap_or_else(|e| e.into_inner());
            if last.is_some_and(|value| value.elapsed() < Duration::from_secs(30)) {
                return Err(ProtocolFailure("bootstrap cooldown is active".into()));
            }
            *last = Some(Instant::now());
        }
        let transport = self.transport()?;
        transport.send_handshake(temp_cid, b"NACK".to_vec())?;
        let (server_init_private, server_init_public) =
            crypto::generate_keypair(crypto::KeyKind::X448)?;
        let tss_salt = crypto::random_bytes(64)?;
        let mut signed_data = server_init_public;
        signed_data.extend_from_slice(&tss_salt);
        let signed = crypto::ed25519_sign(&self.signing_private, &signed_data)?;
        transport.send_handshake(temp_cid, signed)?;

        let client_signed = recv_handshake_required(
            &transport,
            temp_cid,
            handshake_default_timeout(),
            "bootstrap client ephemeral key",
        )?;
        let client_data = crypto::ed25519_verify(client_public, &client_signed)?;
        crypto::parse_framed_key(
            &client_data,
            Some(crypto::KeyKind::X448),
            Some(false),
        )?;
        let dh = crypto::shared_secret(&server_init_private, &client_data)?;
        let current_code = crypto::current_totp(&bootstrap_secret)?;
        let mut tss_input = tss_salt;
        tss_input.extend_from_slice(&dh);
        let tss = crypto::kdf(current_code.as_bytes(), &tss_input, 5)?;

        let mut channel = HandshakeChannel::new();
        let nonce1 = crypto::random_bytes(32)?;
        hs_send(
            &transport,
            temp_cid,
            &tss,
            &mut channel.send_counter,
            b'1',
            &nonce1,
        )?;
        let nonce2 = hs_recv(
            &transport,
            temp_cid,
            &tss,
            &mut channel.receive_counter,
            b'0',
            handshake_default_timeout(),
        )?;
        if nonce2.len() != 32 {
            return Err(ProtocolFailure("invalid bootstrap nonce length".into()));
        }
        let mut both_nonces = nonce1;
        both_nonces.extend_from_slice(&nonce2);
        let nhash = crypto::basic_kdf(&both_nonces, &[], 64);
        let client_hash = hs_recv(
            &transport,
            temp_cid,
            &tss,
            &mut channel.receive_counter,
            b'0',
            handshake_first_timeout(),
        )?;
        if !ct_equal(&client_hash, &nhash) {
            return Err(ProtocolFailure("bootstrap nonce proof mismatch".into()));
        }
        let proof = crypto::basic_kdf(&nhash, &[], 64);
        hs_send(
            &transport,
            temp_cid,
            &tss,
            &mut channel.send_counter,
            b'1',
            &proof,
        )?;

        let (server_second_private, server_second_public) =
            crypto::generate_keypair(crypto::KeyKind::X448)?;
        let server_second_signed =
            crypto::ed25519_sign(&self.signing_private, &server_second_public)?;
        transport.send_handshake(temp_cid, server_second_signed)?;
        let client_second_signed = recv_handshake_required(
            &transport,
            temp_cid,
            handshake_default_timeout(),
            "bootstrap second client ephemeral key",
        )?;
        let client_second_public = crypto::ed25519_verify(client_public, &client_second_signed)?;
        crypto::parse_framed_key(
            &client_second_public,
            Some(crypto::KeyKind::X448),
            Some(false),
        )?;
        let key = crypto::shared_secret(&server_second_private, &client_second_public)?;
        let fid = crypto::random_hex_id(16)?;
        let path = Path::new(AUTH_DIR).join(&fid);
        let auth_blob = crypto::ed25519_sign(&self.signing_private, client_public)?;
        write_atomic(&path, &auth_blob)?;
        let connection_id = transport.connection_id(temp_cid)?;
        let cid = crypto::basic_kdf(client_public, &[], 6);
        self.register_session(
            temp_cid,
            cid,
            Session {
                key,
                send_counter: 3,
                receive_counter: 2,
                admin: false,
                username: Some(fid),
                connection_id,
                last_received_hash: None,
                send_gate: Arc::new(Mutex::new(())),
            },
        )
    }

    fn handshake_admin(self: &Arc<Self>, temp_cid: &[u8], client_init_public: &[u8]) -> PResult<()> {
        crypto::parse_framed_key(
            client_init_public,
            Some(crypto::KeyKind::X448),
            Some(false),
        )?;
        {
            let last = self.last_admin.lock().unwrap_or_else(|e| e.into_inner());
            if last.is_some_and(|value| value.elapsed() < Duration::from_secs(30)) {
                return Err(ProtocolFailure("admin cooldown is active".into()));
            }
        }
        let transport = self.transport()?;
        let (server_init_private, server_init_public) =
            crypto::generate_keypair(crypto::KeyKind::X448)?;
        let tss_salt = crypto::random_bytes(64)?;
        let mut signed_data = server_init_public;
        signed_data.extend_from_slice(&tss_salt);
        let signed = crypto::ed25519_sign(&self.signing_private, &signed_data)?;
        transport.send_handshake(temp_cid, signed)?;
        *self.last_admin.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());

        let dh = crypto::shared_secret(&server_init_private, client_init_public)?;
        let code = crypto::current_totp(&self.admin_totp)?;
        let mut tss_input = tss_salt;
        tss_input.extend_from_slice(&dh);
        let tss = crypto::kdf(code.as_bytes(), &tss_input, 5)?;
        let mut channel = HandshakeChannel::new();
        let nonce1 = crypto::random_bytes(32)?;
        hs_send(
            &transport,
            temp_cid,
            &tss,
            &mut channel.send_counter,
            b'1',
            &nonce1,
        )?;
        let nonce2 = hs_recv(
            &transport,
            temp_cid,
            &tss,
            &mut channel.receive_counter,
            b'0',
            handshake_default_timeout(),
        )?;
        if nonce2.len() != 32 {
            return Err(ProtocolFailure("invalid admin nonce length".into()));
        }
        let mut both_nonces = nonce1;
        both_nonces.extend_from_slice(&nonce2);
        let nhash = crypto::basic_kdf(&both_nonces, &[], 64);
        let client_hash = hs_recv(
            &transport,
            temp_cid,
            &tss,
            &mut channel.receive_counter,
            b'0',
            handshake_first_timeout(),
        )?;
        if !ct_equal(&client_hash, &nhash) {
            return Err(ProtocolFailure("admin nonce proof mismatch".into()));
        }
        let proof = crypto::basic_kdf(&nhash, &[], 64);
        hs_send(
            &transport,
            temp_cid,
            &tss,
            &mut channel.send_counter,
            b'1',
            &proof,
        )?;
        let cid = temp_cid.to_vec();
        let connection_id = transport.connection_id(temp_cid)?;
        self.register_session(
            temp_cid,
            cid,
            Session {
                key: tss,
                send_counter: 3,
                receive_counter: 2,
                admin: true,
                username: None,
                connection_id,
                last_received_hash: None,
                send_gate: Arc::new(Mutex::new(())),
            },
        )
    }

    fn register_session(
        &self,
        temp_cid: &[u8],
        cid: Vec<u8>,
        session: Session,
    ) -> PResult<()> {
        if cid.is_empty() || cid.len() > transport::MAX_CID_BYTES {
            return Err(ProtocolFailure("invalid client id length".into()));
        }
        let pairs = self.allocate_pairs();
        let assignment = encode_port_assignment(&session.key, &pairs)?;
        {
            let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            if sessions.contains_key(&cid) {
                return Err(ProtocolFailure("client id already connected".into()));
            }
            sessions.insert(cid.clone(), Arc::new(Mutex::new(session)));
        }
        self.assigned_pairs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(cid.clone(), pairs);
        let main = self.transport()?;
        if let Err(error) = main.send_handshake(temp_cid, assignment) {
            self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&cid);
            self.assigned_pairs.lock().unwrap_or_else(|e| e.into_inner()).remove(&cid);
            return Err(error.into());
        }
        if let Err(error) = main.auth_finished(temp_cid, cid.clone(), None) {
            self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&cid);
            self.assigned_pairs.lock().unwrap_or_else(|e| e.into_inner()).remove(&cid);
            return Err(error.into());
        }
        Ok(())
    }

    fn dispatch_exchange(&self, cid: Vec<u8>, eid: [u8; 8]) {
        let timeout = exchange_callback_timeout();
        let data = match self.recv_internal(&cid, &eid, Some(timeout)) {
            Ok(Some(data)) => data,
            Ok(None) => {
                eprintln!(
                    "network2: timed out waiting for first payload before on_exchange callback (client_id {}, EID {}, timeout {} ms)",
                    hex::encode(&cid), hex::encode(eid), timeout.as_millis()
                );
                return;
            }
            Err(error) => {
                eprintln!(
                    "network2: failed to receive first payload before on_exchange callback (client_id {}, EID {}): {}",
                    hex::encode(&cid), hex::encode(eid), error
                );
                return;
            }
        };
        let Some(callback) = self.callback.as_ref() else {
            return;
        };
        let (callback, weak_server_object) = Python::attach(|py| {
            let cb = callback.clone_ref(py);
            let weak = self
                .python_self
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|value| value.clone_ref(py));
            (cb, weak)
        });
        let Some(weak_server_object) = weak_server_object else {
            eprintln!(
                "network2: cannot dispatch on_exchange callback for client_id {} (EID {}): Python server object is unavailable",
                hex::encode(&cid), hex::encode(eid)
            );
            return;
        };
        Python::attach(|py| {
            let server_object = match weak_server_object.bind(py).call0() {
                Ok(value) => value,
                Err(error) => {
                    eprintln!(
                        "network2: failed to resolve Python server object for on_exchange callback: {error}"
                    );
                    return;
                }
            };
            if server_object.is_none() {
                eprintln!(
                    "network2: Python server object was dropped before on_exchange callback (client_id {}, EID {})",
                    hex::encode(&cid), hex::encode(eid)
                );
                return;
            }
            let result = callback.bind(py).call1((
                server_object,
                PyBytes::new(py, &eid),
                PyBytes::new(py, &data),
                PyBytes::new(py, &cid),
            ));
            if let Err(error) = result {
                eprintln!("network2 on_exchange callback error: {error}");
            }
        });
    }

    pub fn send(&self, payload: &[u8], eid: Option<&[u8]>, client_id: &[u8]) -> PResult<Vec<u8>> {
        let session_arc = self.session(client_id)?;
        let send_gate = {
            session_arc
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .send_gate
                .clone()
        };
        let _send_guard = send_gate.lock().unwrap_or_else(|e| e.into_inner());
        let exchange: [u8; 8];
        let counter: u64;
        let wire_payload: Vec<u8>;
        {
            let mut session = session_arc.lock().unwrap_or_else(|e| e.into_inner());
            exchange = match eid {
                Some(value) => exact_eid(value)?,
                None => crypto::random_bytes(8)?.try_into().expect("8 random bytes"),
            };
            counter = session.send_counter;
            session.send_counter = session
                .send_counter
                .checked_add(1)
                .ok_or_else(|| ProtocolFailure("send counter exhausted".into()))?;
            let counter_bytes = counter.to_be_bytes();
            let mut aad = Vec::with_capacity(17);
            aad.extend_from_slice(&exchange);
            aad.extend_from_slice(&counter_bytes);
            aad.push(b'1'); // server-to-client
            let encrypted = crypto::encrypt_gcm(payload, &session.key, Some(&aad))?;
            let mut wire = Vec::with_capacity(8 + encrypted.len());
            wire.extend_from_slice(&counter_bytes);
            wire.extend_from_slice(&encrypted);
            wire_payload = wire;
        }
        let pair_index = self.pair_for_eid(client_id, &exchange)
            .ok_or_else(|| ProtocolFailure("client has no assigned port pair".into()))?;
        let ack = self.ack_channel(client_id, pair_index)?;
        let transport = self.data_transport(pair_index)?;
        send_data_with_ack(&ack, counter, || {
            transport.send(client_id, wire_payload.clone(), Some(exchange.to_vec()))?;
            Ok(())
        })?;
        Ok(exchange.to_vec())
    }

    pub fn recv(
        &self,
        client_id: &[u8],
        eid: &[u8],
        timeout: Option<Duration>,
    ) -> PResult<Option<Vec<u8>>> {
        let effective = Some(timeout.unwrap_or(MAX_TIMEOUT).min(MAX_TIMEOUT));
        self.recv_internal(client_id, eid, effective)
    }

    fn recv_internal(
        &self,
        client_id: &[u8],
        eid: &[u8],
        timeout: Option<Duration>,
    ) -> PResult<Option<Vec<u8>>> {
        let exchange = exact_eid(eid)?;
        let session_arc = match self.session(client_id) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        let pair_index = self.pair_for_eid(client_id, &exchange)
            .ok_or_else(|| ProtocolFailure("client has no assigned port pair".into()))?;
        let ack = self.ack_channel(client_id, pair_index)?;
        let transport = self.data_transport(pair_index)?;
        let deadline = timeout.map(|value| Instant::now() + value);
        loop {
            let remaining = deadline.map(|value| value.saturating_duration_since(Instant::now()));
            if remaining.is_some_and(|value| value.is_zero()) {
                return Ok(None);
            }
            let wire = transport.recv(client_id, &exchange, remaining)?;
            let Some(wire) = wire else { return Ok(None) };
            let mut session = session_arc.lock().unwrap_or_else(|e| e.into_inner());
            match decode_data_record(&mut session, &wire, &exchange, b'0')? {
                ReceivedData::Fresh {
                    counter,
                    plaintext,
                    fingerprint,
                } => {
                    // Commit delivery state only after the authenticated ACK
                    // has entered the independent control channel's send queue.
                    ack.send_status(true, b'0', counter)?;
                    session.receive_counter = counter;
                    session.last_received_hash = Some(fingerprint);
                    return Ok(Some(plaintext));
                }
                ReceivedData::Duplicate { counter } => {
                    ack.send_status(true, b'0', counter)?;
                }
                ReceivedData::Rejected { counter } => {
                    ack.send_status(false, b'0', counter)?;
                }
            }
        }
    }

    fn session(&self, cid: &[u8]) -> PResult<Arc<Mutex<Session>>> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(cid)
            .cloned()
            .ok_or_else(|| ProtocolFailure("unknown client id".into()))
    }

    pub fn is_authed(&self, cid: &[u8]) -> bool {
        let session_exists = self.sessions.lock().unwrap_or_else(|e| e.into_inner()).contains_key(cid);
        let Some(pairs) = self.assigned_pairs(cid) else { return false };
        session_exists
            && self.transport().is_ok_and(|transport| transport.is_authed(cid))
            && pairs.iter().all(|pair| {
                self.data_transport(*pair).is_ok_and(|transport| transport.is_authed(cid))
                    && self.ack_channels.lock().unwrap_or_else(|e| e.into_inner())
                        .get(&(cid.to_vec(), *pair))
                        .is_some_and(|channel| !channel.closed.load(Ordering::Acquire))
            })
    }

    pub fn set_backpressure(&self, cid: &[u8], enabled: bool) -> PResult<()> {
        let pairs = self.assigned_pairs(cid)
            .ok_or_else(|| ProtocolFailure("client has no assigned port pairs".into()))?;
        for pair in pairs {
            self.data_transport(pair)?.set_backpressure(cid, enabled)?;
        }
        Ok(())
    }

    pub fn close_client(&self, cid: &[u8], close_socket: bool) -> PResult<()> {
        let pairs = self.assigned_pairs(cid).unwrap_or([0; PORT_PAIRS_PER_CLIENT]);
        if close_socket {
            self.transport()?.close_client(cid)?;
        }
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(cid);
        self.assigned_pairs.lock().unwrap_or_else(|e| e.into_inner()).remove(cid);
        for pair in pairs {
            if close_socket {
                if let Ok(data) = self.data_transport(pair) {
                    let _ = data.close_client(cid);
                }
            }
            self.close_ack_channel_for_pair(cid, pair);
        }
        if close_socket {
            self.pending_bootstrap_totp.lock().unwrap_or_else(|e| e.into_inner()).remove(cid);
        }
        Ok(())
    }

    fn forget_client_generation(&self, cid: &[u8], connection_id: u64) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let should_remove = sessions.get(cid).is_some_and(|session| {
            session.lock().unwrap_or_else(|e| e.into_inner()).connection_id == connection_id
        });
        if should_remove {
            sessions.remove(cid);
            self.pending_bootstrap_totp.lock().unwrap_or_else(|e| e.into_inner()).remove(cid);
        }
        drop(sessions);
        if should_remove {
            let pairs = self.assigned_pairs.lock().unwrap_or_else(|e| e.into_inner())
                .remove(cid).unwrap_or([0; PORT_PAIRS_PER_CLIENT]);
            for pair in pairs {
                if let Ok(data) = self.data_transport(pair) {
                    let _ = data.close_client(cid);
                }
                self.close_ack_channel_for_pair(cid, pair);
            }
        }
    }

    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(transport) = self.transport.lock().unwrap_or_else(|e| e.into_inner()).take() {
            transport.stop();
        }
        let channels = {
            let mut channels = self.ack_channels.lock().unwrap_or_else(|e| e.into_inner());
            channels.drain().map(|(_, channel)| channel).collect::<Vec<_>>()
        };
        for channel in channels {
            channel.close();
        }
        let ack_transports = std::mem::take(
            &mut *self.ack_transports.lock().unwrap_or_else(|e| e.into_inner()),
        );
        for transport in ack_transports {
            transport.stop();
        }
        let data_transports = std::mem::take(
            &mut *self.data_transports.lock().unwrap_or_else(|e| e.into_inner()),
        );
        for transport in data_transports {
            transport.stop();
        }
        self.assigned_pairs.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn require_admin(&self, cid: &[u8]) -> PResult<Arc<Mutex<Session>>> {
        let session = self.session(cid)?;
        if !session.lock().unwrap_or_else(|e| e.into_inner()).admin {
            return Err(ProtocolFailure("admin authentication required".into()));
        }
        Ok(session)
    }

    fn send_json_reply(&self, cid: &[u8], eid: &[u8], value: Value) -> PResult<()> {
        let json_bytes = serde_json::to_vec(&value)
            .map_err(|e| ProtocolFailure(format!("JSON serialization failed: {e}")))?;
        let mut response = Vec::with_capacity(json_bytes.len() + 4);
        response.extend_from_slice(&(json_bytes.len() as u32).to_be_bytes());
        response.extend_from_slice(&json_bytes);
        self.send(&response, Some(eid), cid)?;
        Ok(())
    }

    pub fn setup_bootstrap_totp(&self, cid: &[u8], eid: &[u8]) -> PResult<()> {
        self.require_admin(cid)?;
        let secret = crypto::random_bytes(20)?;
        self.pending_bootstrap_totp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(cid.to_vec(), secret.clone());
        self.send_json_reply(
            cid,
            eid,
            json!({
                "status": "ok",
                "secret": crypto::totp_secret_string(&secret),
                "message": "Scan or save this Auth Key Security Code secret, then verify a current code."
            }),
        )
    }

    pub fn verify_bootstrap_totp(&self, cid: &[u8], eid: &[u8], code: &str) -> PResult<()> {
        self.require_admin(cid)?;
        let secret = self
            .pending_bootstrap_totp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(cid)
            .cloned()
            .ok_or_else(|| ProtocolFailure("no pending bootstrap TOTP secret".into()))?;
        let normalized: String = code.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        if !crypto::verify_totp(&secret, &normalized, 1)? {
            self.send_json_reply(
                cid,
                eid,
                json!({"status":"error", "verified":false, "message":"Invalid code"}),
            )?;
            return Ok(());
        }
        let encrypted = crypto::encrypt_gcm(&secret, &self.at_rest_key, None)?;
        write_atomic(&Path::new(SERVER_DIR).join(BOOTSTRAP_TOTP_FILE), &encrypted)?;
        *self.bootstrap_totp.lock().unwrap_or_else(|e| e.into_inner()) = Some(secret);
        self.pending_bootstrap_totp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(cid);
        self.send_json_reply(
            cid,
            eid,
            json!({"status":"ok", "verified":true, "message":"Bootstrap TOTP configured"}),
        )
    }

    pub fn bootstrap_status(&self, cid: &[u8], eid: &[u8]) -> PResult<()> {
        self.require_admin(cid)?;
        self.send_json_reply(
            cid,
            eid,
            json!({
                "status":"ok",
                "enabled":self.enable_bootstrap.load(Ordering::Acquire),
                "totp_configured":self.bootstrap_totp.lock().unwrap_or_else(|e| e.into_inner()).is_some()
            }),
        )
    }

    pub fn bootstrapping_enabled(&self, cid: &[u8], eid: &[u8]) -> PResult<()> {
        self.session(cid)?;
        self.send_json_reply(
            cid,
            eid,
            json!({"status":"ok", "enabled":self.enable_bootstrap.load(Ordering::Acquire)}),
        )
    }

    pub fn enable_bootstrap(&self, cid: &[u8], eid: &[u8], enabled: bool) -> PResult<()> {
        self.require_admin(cid)?;
        if enabled
            && self
                .bootstrap_totp
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_none()
        {
            return Err(ProtocolFailure("configure and verify bootstrap TOTP before enabling bootstrap".into()));
        }
        if !enabled {
            self.pending_bootstrap_totp
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
        }
        self.enable_bootstrap.store(enabled, Ordering::Release);
        self.send_json_reply(cid, eid, json!({"status":"ok", "enabled":enabled}))
    }

    pub fn list_users(&self, cid: &[u8], eid: &[u8]) -> PResult<()> {
        self.require_admin(cid)?;
        let mut users: Vec<String> = fs::read_dir(AUTH_DIR)?
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        users.sort_by_key(|name| name.to_ascii_lowercase());
        self.send_json_reply(cid, eid, json!({"status":"ok", "users":users}))
    }

    pub fn list_connections(&self, cid: &[u8], eid: &[u8]) -> PResult<()> {
        self.require_admin(cid)?;
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let mut connections: Vec<Value> = sessions
            .iter()
            .filter_map(|(id, session)| {
                let session = session.lock().unwrap_or_else(|e| e.into_inner());
                if session.admin {
                    None
                } else {
                    Some(json!({
                        "cid":hex::encode(id),
                        "username":session.username.clone().unwrap_or_default()
                    }))
                }
            })
            .collect();
        connections.sort_by_key(|entry| {
            entry["username"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase()
        });
        self.send_json_reply(
            cid,
            eid,
            json!({"status":"ok", "connections":connections}),
        )
    }

    pub fn server_cert(&self, cid: &[u8], eid: &[u8]) -> PResult<()> {
        self.session(cid)?;
        self.send_json_reply(
            cid,
            eid,
            json!({"status":"ok", "cert":hex::encode(&self.signing_public)}),
        )
    }

    pub fn rename_username(
        &self,
        cid: &[u8],
        eid: &[u8],
        target: &[u8],
        new_username: &str,
    ) -> PResult<()> {
        self.require_admin(cid)?;
        if !valid_username(new_username) {
            return Err(ProtocolFailure("invalid new username".into()));
        }
        let (target_cid, old_name) = self.resolve_target(target)?;
        let old_path = Path::new(AUTH_DIR).join(&old_name);
        let new_path = Path::new(AUTH_DIR).join(new_username);
        if new_path.exists() {
            return Err(ProtocolFailure("username already exists".into()));
        }
        let mut renamed_files = 0usize;
        if old_path.exists() {
            fs::rename(&old_path, &new_path)?;
            renamed_files = 1;
        }
        let mut connected = false;
        if let Some(target_cid) = target_cid {
            if let Some(session) = self
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&target_cid)
                .cloned()
            {
                session.lock().unwrap_or_else(|e| e.into_inner()).username =
                    Some(new_username.to_string());
                connected = true;
            }
        }
        self.send_json_reply(
            cid,
            eid,
            json!({
                "ok":true,
                "old_username":old_name,
                "username":new_username,
                "connected":connected,
                "renamed_files":renamed_files,
                "status":"ok"
            }),
        )
    }

    pub fn deauth_client(&self, cid: &[u8], eid: &[u8], target: &[u8]) -> PResult<()> {
        self.require_admin(cid)?;
        let (target_cid, username) = self.resolve_target(target)?;
        let mut deauthenticated = false;
        let mut name = username.clone();
        if let Some(target_cid) = target_cid {
            if let Some(session) = self
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&target_cid)
            {
                name = session
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .username
                    .clone()
                    .unwrap_or(username);
            }
        }
        let path = Path::new(AUTH_DIR).join(&name);
        if path.exists() {
            fs::remove_file(path)?;
            deauthenticated = true;
        }
        self.send_json_reply(
            cid,
            eid,
            json!({"status":"ok", "deauthenticated":deauthenticated, "username":name}),
        )
    }

    pub fn disconnect_client(&self, cid: &[u8], eid: &[u8], target: &[u8]) -> PResult<()> {
        self.require_admin(cid)?;
        let (target_cid, username) = self.resolve_target(target)?;
        let target_cid = target_cid.ok_or_else(|| ProtocolFailure("target is not connected".into()))?;
        self.transport()?.close_client(&target_cid)?;
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&target_cid);
        self.assigned_pairs.lock().unwrap_or_else(|e| e.into_inner()).remove(&target_cid);
        self.close_ack_channels(&target_cid);
        self.send_json_reply(
            cid,
            eid,
            json!({"status":"ok", "disconnected":true, "username":username}),
        )
    }

    fn resolve_target(&self, target: &[u8]) -> PResult<(Option<Vec<u8>>, String)> {
        if target.len() == 6 || target.len() == 8 {
            if let Some(session) = self
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(target)
            {
                let username = session
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .username
                    .clone()
                    .unwrap_or_default();
                return Ok((Some(target.to_vec()), username));
            }
        }
        let text = std::str::from_utf8(target)
            .map_err(|_| ProtocolFailure("target must be a client id, hex id, or username".into()))?;
        if let Ok(id) = hex::decode(text) {
            if id.len() == 6 || id.len() == 8 {
                if let Some(session) = self
                    .sessions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&id)
                {
                    let username = session
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .username
                        .clone()
                        .unwrap_or_default();
                    return Ok((Some(id), username));
                }
            }
        }
        let safe = validate_stored_username(text)?;
        if let Some((id, _)) = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(_, session)| {
                session
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .username
                    .as_deref()
                    == Some(safe.as_str())
            })
        {
            return Ok((Some(id.clone()), safe));
        }
        if Path::new(AUTH_DIR).join(&safe).exists() {
            Ok((None, safe))
        } else {
            Err(ProtocolFailure("target client or username was not found".into()))
        }
    }
}


impl Drop for ProtocolServer {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct ProtocolClient {
    base_port: u16,
    // The base connection carries only handshake/control messages.
    transport: Mutex<Option<transport::TransportClient>>,
    data_transports: Mutex<HashMap<usize, transport::TransportClient>>,
    ack_transports: Mutex<HashMap<usize, transport::TransportClient>>,
    ack_channels: Mutex<HashMap<usize, Arc<AckChannel>>>,
    assigned_pairs: Mutex<Option<[usize; PORT_PAIRS_PER_CLIENT]>>,
    session: Mutex<Option<Session>>,
    callback: Option<Py<PyAny>>,
    python_self: Mutex<Option<Py<PyAny>>>,
    closed: AtomicBool,
}

impl ProtocolClient {
    pub fn connect(
        host: String,
        port: u16,
        password: String,
        admin_auth_code: Option<String>,
        callback: Option<Py<PyAny>>,
        simult_exchanges: usize,
        _requested_ack_port: Option<u16>,
    ) -> PResult<Arc<Self>> {
        if !(1..=64).contains(&simult_exchanges) {
            return Err(ProtocolFailure("simult_exchanges must be between 1 and 64".into()));
        }
        if port == 0 || port.checked_add((PORT_PAIR_COUNT * 2) as u16).is_none() {
            return Err(ProtocolFailure(
                "base port must be between 1 and 65515 so all 21 ports fit".into(),
            ));
        }
        let is_admin = admin_auth_code.is_some();
        let identity = if is_admin {
            None
        } else {
            Some(prepare_client_identity(&password)?)
        };
        let client = Arc::new(Self {
            base_port: port,
            transport: Mutex::new(None),
            data_transports: Mutex::new(HashMap::new()),
            ack_transports: Mutex::new(HashMap::new()),
            ack_channels: Mutex::new(HashMap::new()),
            assigned_pairs: Mutex::new(None),
            session: Mutex::new(None),
            callback,
            python_self: Mutex::new(None),
            closed: AtomicBool::new(false),
        });
        let noop: Arc<dyn Fn([u8; 8]) + Send + Sync> = Arc::new(|_| {});
        let transport = transport::TransportClient::connect(&host, port, simult_exchanges, noop)?;
        *client.transport.lock().unwrap_or_else(|e| e.into_inner()) = Some(transport.clone());
        let auth_result = if let Some(code) = admin_auth_code {
            client.handshake_admin(&transport, &code)
        } else {
            client.handshake_non_admin(&transport, identity.expect("non-admin identity"))
        };
        if let Err(error) = auth_result {
            client.close();
            return Err(error);
        }
        if let Err(error) = client.connect_assigned_pairs(&host, simult_exchanges) {
            client.close();
            return Err(error);
        }
        Ok(client)
    }

    fn receive_pair_assignment(
        &self,
        transport: &transport::TransportClient,
        session_key: &[u8],
    ) -> PResult<()> {
        let frame = recv_client_handshake_required(
            transport,
            ACK_CONNECT_TIMEOUT,
            "encrypted port-pair assignment",
        )?;
        let pairs = decode_port_assignment(&frame, session_key)?;
        *self.assigned_pairs.lock().unwrap_or_else(|e| e.into_inner()) = Some(pairs);
        Ok(())
    }

    fn assigned_pairs(&self) -> PResult<[usize; PORT_PAIRS_PER_CLIENT]> {
        self.assigned_pairs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .copied()
            .ok_or_else(|| ProtocolFailure("server has not assigned bulk port pairs".into()))
    }

    fn pair_for_eid(&self, eid: &[u8; 8]) -> PResult<usize> {
        Ok(selected_pair(eid, &self.assigned_pairs()?))
    }

    fn data_transport(&self, pair_index: usize) -> PResult<transport::TransportClient> {
        self.data_transports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&pair_index)
            .cloned()
            .ok_or_else(|| ProtocolFailure("bulk transport for EID is not connected".into()))
    }

    fn ack_channel(&self, pair_index: usize) -> PResult<Arc<AckChannel>> {
        self.ack_channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&pair_index)
            .cloned()
            .ok_or_else(|| ProtocolFailure("ACK channel for EID is not connected".into()))
    }

    fn connect_assigned_pairs(
        self: &Arc<Self>,
        host: &str,
        simult_exchanges: usize,
    ) -> PResult<()> {
        for pair_index in self.assigned_pairs()? {
            self.connect_data_port(host, pair_index, simult_exchanges)?;
            self.connect_ack_channel(host, pair_index, simult_exchanges)?;
        }
        Ok(())
    }

    fn connect_data_port(
        self: &Arc<Self>,
        host: &str,
        pair_index: usize,
        simult_exchanges: usize,
    ) -> PResult<()> {
        let weak = Arc::downgrade(self);
        let callback: Arc<dyn Fn([u8; 8]) + Send + Sync> = Arc::new(move |eid| {
            if let Some(client) = weak.upgrade() {
                if client.pair_for_eid(&eid).ok() == Some(pair_index) {
                    client.dispatch_exchange(eid);
                } else {
                    eprintln!("network2: server sent EID to an unassigned bulk pair");
                }
            }
        });
        let data_transport = transport::TransportClient::connect(
            host,
            self.base_port + 1 + (pair_index as u16 * 2),
            simult_exchanges,
            callback,
        )?;

        let (control_key, key_id) = {
            let session = self.session.lock().unwrap_or_else(|e| e.into_inner());
            let session = session.as_ref()
                .ok_or_else(|| ProtocolFailure("client is not authenticated".into()))?;
            let control_key = ack_control_key(&session.key);
            let key_id = ack_control_key_id(&control_key);
            (control_key, key_id)
        };

        let setup = (|| -> PResult<()> {
            let client_nonce = crypto::random_bytes(32)?;
            let mut hello_plain = DATA_HELLO_TAG.to_vec();
            hello_plain.extend_from_slice(&client_nonce);
            let hello_aad = port_handshake_aad(b"data", b"client-hello", pair_index, &key_id);
            let hello_encrypted = crypto::encrypt_gcm(
                &hello_plain, &control_key, Some(&hello_aad),
            )?;
            let mut hello = DATA_HELLO_MAGIC.to_vec();
            hello.extend_from_slice(&key_id);
            hello.extend_from_slice(&hello_encrypted);
            data_transport.send_handshake(hello)?;

            let challenge = recv_client_handshake_required(
                &data_transport, ACK_CONNECT_TIMEOUT, "bulk-channel challenge",
            )?;
            if challenge.len() < DATA_CHALLENGE_MAGIC.len() + 8 + crypto::AES_GCM_OVERHEAD
                || &challenge[..DATA_CHALLENGE_MAGIC.len()] != DATA_CHALLENGE_MAGIC
            {
                return Err(ProtocolFailure("invalid bulk-channel challenge".into()));
            }
            let challenge_aad =
                port_handshake_aad(b"data", b"server-challenge", pair_index, &key_id);
            let challenge_plain = crypto::decrypt_gcm(
                &challenge[DATA_CHALLENGE_MAGIC.len()..],
                &control_key,
                Some(&challenge_aad),
            )?;
            if challenge_plain.len() != 72
                || !ct_equal(&challenge_plain[..8], DATA_CHALLENGE_TAG)
                || !ct_equal(&challenge_plain[8..40], &client_nonce)
            {
                return Err(ProtocolFailure("bulk-channel challenge proof failed".into()));
            }
            let server_nonce = challenge_plain[40..72].to_vec();
            let channel_key = port_channel_key(
                &control_key, &client_nonce, &server_nonce, b"data", pair_index,
            );

            let mut finish_plain = DATA_FINISH_TAG.to_vec();
            finish_plain.extend_from_slice(&client_nonce);
            finish_plain.extend_from_slice(&server_nonce);
            let finish_aad = port_handshake_aad(b"data", b"client-finish", pair_index, &key_id);
            let finish_encrypted = crypto::encrypt_gcm(
                &finish_plain, &control_key, Some(&finish_aad),
            )?;
            let mut finish = DATA_FINISH_MAGIC.to_vec();
            finish.extend_from_slice(&finish_encrypted);
            data_transport.send_handshake(finish)?;

            let ready = recv_client_handshake_required(
                &data_transport, ACK_CONNECT_TIMEOUT, "bulk-channel ready proof",
            )?;
            if ready.len() < DATA_READY_MAGIC.len() + 8 + crypto::AES_GCM_OVERHEAD
                || &ready[..DATA_READY_MAGIC.len()] != DATA_READY_MAGIC
            {
                return Err(ProtocolFailure("invalid bulk-channel ready frame".into()));
            }
            let ready_aad = port_handshake_aad(b"data", b"server-ready", pair_index, &key_id);
            let ready_plain = crypto::decrypt_gcm(
                &ready[DATA_READY_MAGIC.len()..],
                &channel_key,
                Some(&ready_aad),
            )?;
            if ready_plain.len() != 9
                || !ct_equal(&ready_plain[..8], DATA_READY_TAG)
                || ready_plain[8] as usize != pair_index
            {
                return Err(ProtocolFailure("bulk-channel ready proof failed".into()));
            }
            data_transport.auth_finished()?;
            Ok(())
        })();

        if let Err(error) = setup {
            data_transport.close();
            return Err(error);
        }
        self.data_transports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(pair_index, data_transport);
        Ok(())
    }

    fn connect_ack_channel(
        &self,
        host: &str,
        pair_index: usize,
        simult_exchanges: usize,
    ) -> PResult<()> {
        let noop: Arc<dyn Fn([u8; 8]) + Send + Sync> = Arc::new(|_| {});
        let ack_transport = transport::TransportClient::connect(
            host,
            self.base_port + 2 + (pair_index as u16 * 2),
            simult_exchanges,
            noop,
        )?;

        let (control_key, key_id) = {
            let session = self.session.lock().unwrap_or_else(|e| e.into_inner());
            let session = session
                .as_ref()
                .ok_or_else(|| ProtocolFailure("client is not authenticated".into()))?;
            let key = ack_control_key(&session.key);
            let id = ack_control_key_id(&key);
            (key, id)
        };

        let setup = (|| -> PResult<Arc<AckChannel>> {
            let client_nonce = crypto::random_bytes(32)?;
            let mut hello_plain = Vec::with_capacity(40);
            hello_plain.extend_from_slice(ACK_HELLO_TAG);
            hello_plain.extend_from_slice(&client_nonce);
            let hello_aad = port_handshake_aad(b"ack", b"client-hello", pair_index, &key_id);
            let hello_encrypted =
                crypto::encrypt_gcm(&hello_plain, &control_key, Some(&hello_aad))?;
            let mut hello = ACK_HELLO_MAGIC.to_vec();
            hello.extend_from_slice(&key_id);
            hello.extend_from_slice(&hello_encrypted);
            ack_transport.send_handshake(hello)?;

            let challenge = recv_client_handshake_required(
                &ack_transport,
                ACK_CONNECT_TIMEOUT,
                "ACK-channel challenge",
            )?;
            if challenge.len() < ACK_CHALLENGE_MAGIC.len() + 8 + crypto::AES_GCM_OVERHEAD
                || &challenge[..ACK_CHALLENGE_MAGIC.len()] != ACK_CHALLENGE_MAGIC
            {
                return Err(ProtocolFailure("invalid ACK-channel challenge".into()));
            }
            let challenge_aad =
                port_handshake_aad(b"ack", b"server-challenge", pair_index, &key_id);
            let challenge_plain = crypto::decrypt_gcm(
                &challenge[ACK_CHALLENGE_MAGIC.len()..],
                &control_key,
                Some(&challenge_aad),
            )?;
            if challenge_plain.len() != 72
                || !ct_equal(&challenge_plain[..8], ACK_CHALLENGE_TAG)
                || !ct_equal(&challenge_plain[8..40], &client_nonce)
            {
                return Err(ProtocolFailure("ACK-channel challenge proof failed".into()));
            }
            let server_nonce = challenge_plain[40..72].to_vec();
            let channel_key = port_channel_key(
                &control_key, &client_nonce, &server_nonce, b"ack", pair_index,
            );

            let mut finish_plain = Vec::with_capacity(72);
            finish_plain.extend_from_slice(ACK_FINISH_TAG);
            finish_plain.extend_from_slice(&client_nonce);
            finish_plain.extend_from_slice(&server_nonce);
            let finish_aad = port_handshake_aad(b"ack", b"client-finish", pair_index, &key_id);
            let finish_encrypted =
                crypto::encrypt_gcm(&finish_plain, &control_key, Some(&finish_aad))?;
            let mut finish = ACK_FINISH_MAGIC.to_vec();
            finish.extend_from_slice(&finish_encrypted);
            ack_transport.send_handshake(finish)?;
            ack_transport.auth_finished()?;

            let ready = ack_transport
                .recv(&ACK_EID, Some(ACK_CONNECT_TIMEOUT))?
                .ok_or_else(|| ProtocolFailure("ACK-channel ready message timed out".into()))?;
            if ready.len() < 8 + crypto::AES_GCM_OVERHEAD {
                return Err(ProtocolFailure("ACK-channel ready message is too short".into()));
            }
            let ready_counter = u64::from_be_bytes(
                ready[..8].try_into().expect("eight-byte ready counter"),
            );
            let ready_aad = ack_record_aad(b'1', ready_counter);
            let ready_plain = crypto::decrypt_gcm(&ready[8..], &channel_key, Some(&ready_aad))?;
            if ready_counter != 1 || !ct_equal(&ready_plain, ACK_READY_TAG) {
                return Err(ProtocolFailure("ACK-channel ready proof failed".into()));
            }
            Ok(Arc::new(AckChannel::client(
                channel_key,
                ack_transport.clone(),
            )))
        })();

        let channel = match setup {
            Ok(channel) => channel,
            Err(error) => {
                ack_transport.close();
                return Err(error);
            }
        };
        if let Err(error) = spawn_client_ack_reader(ack_transport.clone(), channel.clone()) {
            channel.close();
            ack_transport.close();
            return Err(error);
        }
        self.ack_transports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(pair_index, ack_transport);
        self.ack_channels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(pair_index, channel);
        Ok(())
    }

    fn ack_channel_for_eid(&self, eid: &[u8; 8]) -> PResult<Arc<AckChannel>> {
        let pair_index = self.pair_for_eid(eid)?;
        self.ack_channel(pair_index)
    }

    pub fn set_python_self(&self, object: Py<PyAny>) {
        let weak = Python::attach(|py| -> PyResult<Py<PyAny>> {
            Ok(py
                .import("weakref")?
                .getattr("ref")?
                .call1((object.bind(py),))?
                .unbind())
        })
        .expect("network2 wrapper must support weak references");
        *self.python_self.lock().unwrap_or_else(|e| e.into_inner()) = Some(weak);
    }

    fn dispatch_exchange(&self, eid: [u8; 8]) {
        let Ok(Some(data)) = self.recv_internal(&eid, Some(EXCHANGE_CALLBACK_TIMEOUT)) else {
            return;
        };
        let Some(callback) = self.callback.as_ref() else { return };
        let (callback, weak_client_object) = Python::attach(|py| {
            let cb = callback.clone_ref(py);
            let weak = self
                .python_self
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|value| value.clone_ref(py));
            (cb, weak)
        });
        let Some(weak_client_object) = weak_client_object else { return };
        Python::attach(|py| {
            let Ok(client_object) = weak_client_object.bind(py).call0() else { return };
            if client_object.is_none() {
                return;
            }
            let result = callback.bind(py).call1((
                client_object,
                PyBytes::new(py, &eid),
                PyBytes::new(py, &data),
            ));
            if let Err(error) = result {
                eprintln!("network2 on_exchange callback error: {error}");
            }
        });
    }

    fn handshake_non_admin(
        &self,
        transport: &transport::TransportClient,
        identity: ClientIdentity,
    ) -> PResult<()> {
        transport.send_handshake(identity.signing_public.clone())?;
        let server_cert = recv_client_handshake_required(
            transport,
            handshake_first_timeout(),
            "server certificate",
        )?;
        crypto::parse_framed_key(
            &server_cert,
            Some(crypto::KeyKind::Ed448),
            Some(false),
        )?;
        if let Some(pinned) = identity.server_cert.as_ref() {
            if !ct_equal(pinned, &server_cert) {
                return Err(ProtocolFailure("server certificate mismatch".into()));
            }
        } else {
            let typed = prompt_line("Server certificate (hex): ")?;
            let expected = hex::decode(typed.trim())
                .map_err(|_| ProtocolFailure("invalid server certificate hex".into()))?;
            if !ct_equal(&expected, &server_cert) {
                return Err(ProtocolFailure("server certificate mismatch".into()));
            }
        }

        let status = recv_client_handshake_required(
            transport,
            handshake_default_timeout(),
            "server authentication status",
        )?;
        if status == b"ACK" {
            let signed_server_ephemeral = recv_client_handshake_required(
                transport,
                handshake_default_timeout(),
                "server signed ephemeral key",
            )?;
            let server_ephemeral =
                crypto::ed25519_verify(&server_cert, &signed_server_ephemeral)?;
            crypto::parse_framed_key(
                &server_ephemeral,
                Some(crypto::KeyKind::X448),
                Some(false),
            )?;
            let (client_ephemeral_private, client_ephemeral_public) =
                crypto::generate_keypair(crypto::KeyKind::X448)?;
            let client_signed =
                crypto::ed25519_sign(&identity.signing_private, &client_ephemeral_public)?;
            transport.send_handshake(client_signed)?;
            let key = crypto::shared_secret(&client_ephemeral_private, &server_ephemeral)?;
            self.store_client_cert_and_session(
                transport,
                &identity,
                &server_cert,
                key,
                1,
                0,
            )?;
            return Ok(());
        }
        if status != b"NACK" {
            return Err(ProtocolFailure("authentication denied".into()));
        }
        let code = identity
            .bootstrap_code
            .as_ref()
            .ok_or_else(|| ProtocolFailure("authentication denied".into()))?;
        let signed_init = recv_client_handshake_required(
            transport,
            handshake_default_timeout(),
            "bootstrap server ephemeral key",
        )?;
        let init_data = crypto::ed25519_verify(&server_cert, &signed_init)?;
        if init_data.len() != 57 + 64 {
            return Err(ProtocolFailure("malformed bootstrap ephemeral/salt".into()));
        }
        let server_init_public = &init_data[..57];
        crypto::parse_framed_key(
            server_init_public,
            Some(crypto::KeyKind::X448),
            Some(false),
        )?;
        let tss_salt = &init_data[57..];
        let (client_init_private, client_init_public) =
            crypto::generate_keypair(crypto::KeyKind::X448)?;
        let client_init_signed =
            crypto::ed25519_sign(&identity.signing_private, &client_init_public)?;
        transport.send_handshake(client_init_signed)?;
        let dh = crypto::shared_secret(&client_init_private, server_init_public)?;
        let mut tss_input = tss_salt.to_vec();
        tss_input.extend_from_slice(&dh);
        let tss = crypto::kdf(code.as_bytes(), &tss_input, 5)?;

        let mut channel = HandshakeChannel::new();
        let nonce1 = hs_recv_client(
            transport,
            &tss,
            &mut channel.receive_counter,
            b'1',
            handshake_first_timeout(),
        )?;
        if nonce1.len() != 32 {
            return Err(ProtocolFailure("invalid bootstrap server nonce length".into()));
        }
        let nonce2 = crypto::random_bytes(32)?;
        hs_send_client(
            transport,
            &tss,
            &mut channel.send_counter,
            b'0',
            &nonce2,
        )?;
        let mut both_nonces = nonce1;
        both_nonces.extend_from_slice(&nonce2);
        let nhash = crypto::basic_kdf(&both_nonces, &[], 64);
        hs_send_client(
            transport,
            &tss,
            &mut channel.send_counter,
            b'0',
            &nhash,
        )?;
        let server_proof = hs_recv_client(
            transport,
            &tss,
            &mut channel.receive_counter,
            b'1',
            handshake_first_timeout(),
        )?;
        let expected_proof = crypto::basic_kdf(&nhash, &[], 64);
        if !ct_equal(&server_proof, &expected_proof) {
            return Err(ProtocolFailure("bootstrap server proof mismatch".into()));
        }
        let signed_server_second = recv_client_handshake_required(
            transport,
            handshake_default_timeout(),
            "bootstrap second server ephemeral key",
        )?;
        let server_second_public =
            crypto::ed25519_verify(&server_cert, &signed_server_second)?;
        crypto::parse_framed_key(
            &server_second_public,
            Some(crypto::KeyKind::X448),
            Some(false),
        )?;
        let (client_second_private, client_second_public) =
            crypto::generate_keypair(crypto::KeyKind::X448)?;
        let client_second_signed =
            crypto::ed25519_sign(&identity.signing_private, &client_second_public)?;
        transport.send_handshake(client_second_signed)?;
        let key = crypto::shared_secret(&client_second_private, &server_second_public)?;
        self.store_client_cert_and_session(
            transport,
            &identity,
            &server_cert,
            key,
            3,
            2,
        )?;
        Ok(())
    }

    fn handshake_admin(&self, transport: &transport::TransportClient, code: &str) -> PResult<()> {
        if code.is_empty() {
            return Err(ProtocolFailure("admin authentication code cannot be empty".into()));
        }
        let (client_init_private, client_init_public) =
            crypto::generate_keypair(crypto::KeyKind::X448)?;
        let mut first = ADMIN_PREFIX.to_vec();
        first.extend_from_slice(&client_init_public);
        transport.send_handshake(first)?;
        let server_cert_input = prompt_line("Server certificate (hex): ")?;
        let expected_cert = hex::decode(server_cert_input.trim())
            .map_err(|_| ProtocolFailure("invalid server certificate hex".into()))?;
        let server_cert = recv_client_handshake_required(
            transport,
            handshake_first_timeout(),
            "server certificate",
        )?;
        if !ct_equal(&expected_cert, &server_cert) {
            return Err(ProtocolFailure("server certificate mismatch".into()));
        }
        crypto::parse_framed_key(
            &server_cert,
            Some(crypto::KeyKind::Ed448),
            Some(false),
        )?;
        let signed_init = recv_client_handshake_required(
            transport,
            handshake_first_timeout(),
            "admin server signed ephemeral key",
        )?;
        let init_data = crypto::ed25519_verify(&server_cert, &signed_init)?;
        if init_data.len() != 57 + 64 {
            return Err(ProtocolFailure("malformed admin ephemeral/salt".into()));
        }
        let server_init_public = &init_data[..57];
        let dh = crypto::shared_secret(&client_init_private, server_init_public)?;
        let mut tss_input = init_data[57..].to_vec();
        tss_input.extend_from_slice(&dh);
        let tss = crypto::kdf(code.as_bytes(), &tss_input, 5)?;
        let mut channel = HandshakeChannel::new();
        let nonce1 = hs_recv_client(
            transport,
            &tss,
            &mut channel.receive_counter,
            b'1',
            handshake_first_timeout(),
        )?;
        let nonce2 = crypto::random_bytes(32)?;
        hs_send_client(
            transport,
            &tss,
            &mut channel.send_counter,
            b'0',
            &nonce2,
        )?;
        let mut both_nonces = nonce1;
        both_nonces.extend_from_slice(&nonce2);
        let nhash = crypto::basic_kdf(&both_nonces, &[], 64);
        hs_send_client(
            transport,
            &tss,
            &mut channel.send_counter,
            b'0',
            &nhash,
        )?;
        let proof = hs_recv_client(
            transport,
            &tss,
            &mut channel.receive_counter,
            b'1',
            handshake_first_timeout(),
        )?;
        if !ct_equal(&proof, &crypto::basic_kdf(&nhash, &[], 64)) {
            return Err(ProtocolFailure("admin server proof mismatch".into()));
        }
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(Session {
            key: tss,
            send_counter: 3,
            receive_counter: 2,
            admin: true,
            username: None,
            connection_id: 1,
            last_received_hash: None,
            send_gate: Arc::new(Mutex::new(())),
        });
        transport.auth_finished()?;
        Ok(())
    }

    fn store_client_cert_and_session(
        &self,
        transport: &transport::TransportClient,
        identity: &ClientIdentity,
        server_cert: &[u8],
        key: Vec<u8>,
        send_counter: u64,
        receive_counter: u64,
    ) -> PResult<()> {
        let encrypted_private = crypto::encrypt_gcm(
            &identity.signing_private,
            &identity.at_rest_key,
            None,
        )?;
        let cert_signature = crypto::ed25519_sign(&identity.signing_private, server_cert)?;
        write_atomic(&Path::new(CLIENT_DIR).join(CLIENT_AUTH_FILE), &encrypted_private)?;
        write_atomic(&Path::new(CLIENT_DIR).join(CLIENT_SALT_FILE), &identity.salt)?;
        write_atomic(
            &Path::new(CLIENT_DIR).join(CLIENT_SERVER_CERT_FILE),
            &cert_signature,
        )?;
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(Session {
            key,
            send_counter,
            receive_counter,
            admin: false,
            username: None,
            connection_id: 1,
            last_received_hash: None,
            send_gate: Arc::new(Mutex::new(())),
        });
        transport.auth_finished()?;
        Ok(())
    }

    pub fn send(&self, payload: &[u8], eid: Option<&[u8]>) -> PResult<Vec<u8>> {
        let send_gate = {
            let session_guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
            session_guard
                .as_ref()
                .ok_or_else(|| ProtocolFailure("client is not authenticated".into()))?
                .send_gate
                .clone()
        };
        let _send_guard = send_gate.lock().unwrap_or_else(|e| e.into_inner());
        let exchange: [u8; 8];
        let counter: u64;
        let wire_payload: Vec<u8>;
        {
            let mut session_guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
            let session = session_guard
                .as_mut()
                .ok_or_else(|| ProtocolFailure("client is not authenticated".into()))?;
            exchange = match eid {
                Some(value) => exact_eid(value)?,
                None => crypto::random_bytes(8)?.try_into().expect("8 random bytes"),
            };
            counter = session.send_counter;
            session.send_counter = session
                .send_counter
                .checked_add(1)
                .ok_or_else(|| ProtocolFailure("send counter exhausted".into()))?;
            let counter_bytes = counter.to_be_bytes();
            let mut aad = Vec::with_capacity(17);
            aad.extend_from_slice(&exchange);
            aad.extend_from_slice(&counter_bytes);
            aad.push(b'0'); // client-to-server
            let encrypted = crypto::encrypt_gcm(payload, &session.key, Some(&aad))?;
            let mut wire = Vec::with_capacity(8 + encrypted.len());
            wire.extend_from_slice(&counter_bytes);
            wire.extend_from_slice(&encrypted);
            wire_payload = wire;
        }
        let ack = self.ack_channel()?;
        let transport = self.transport()?;
        send_data_with_ack(&ack, counter, || {
            transport.send(wire_payload.clone(), Some(exchange.to_vec()))?;
            Ok(())
        })?;
        Ok(exchange.to_vec())
    }

    pub fn recv(&self, eid: &[u8], timeout: Option<Duration>) -> PResult<Option<Vec<u8>>> {
        // Finite public receive waits are capped at ten seconds; None remains
        // an intentional infinite wait on the client API.
        self.recv_internal(eid, timeout.map(|value| value.min(MAX_TIMEOUT)))
    }

    fn recv_internal(&self, eid: &[u8], timeout: Option<Duration>) -> PResult<Option<Vec<u8>>> {
        let exchange = exact_eid(eid)?;
        let ack = self.ack_channel()?;
        let transport = self.transport()?;
        let deadline = timeout.map(|value| Instant::now() + value);
        loop {
            let remaining = deadline.map(|value| value.saturating_duration_since(Instant::now()));
            if remaining.is_some_and(|value| value.is_zero()) {
                return Ok(None);
            }
            let wire = transport.recv(&exchange, remaining)?;
            let Some(wire) = wire else { return Ok(None) };
            let mut session_guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
            let session = session_guard
                .as_mut()
                .ok_or_else(|| ProtocolFailure("client is not authenticated".into()))?;
            match decode_data_record(session, &wire, &exchange, b'1')? {
                ReceivedData::Fresh {
                    counter,
                    plaintext,
                    fingerprint,
                } => {
                    ack.send_status(true, b'1', counter)?;
                    session.receive_counter = counter;
                    session.last_received_hash = Some(fingerprint);
                    return Ok(Some(plaintext));
                }
                ReceivedData::Duplicate { counter } => {
                    ack.send_status(true, b'1', counter)?;
                }
                ReceivedData::Rejected { counter } => {
                    ack.send_status(false, b'1', counter)?;
                }
            }
        }
    }

    fn transport(&self) -> PResult<transport::TransportClient> {
        self.transport
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
            .ok_or_else(|| ProtocolFailure("client transport is not connected".into()))
    }

    pub fn set_backpressure(&self, enabled: bool) -> PResult<()> {
        self.transport()?.set_backpressure(enabled);
        Ok(())
    }

    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(channel) = self
            .ack_channel
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            channel.close();
        }
        if let Some(transport) = self
            .ack_transport
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            transport.close();
        }
        if let Some(transport) = self
            .transport
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            transport.close();
        }
        self.session.lock().unwrap_or_else(|e| e.into_inner()).take();
    }

    pub fn is_authed(&self) -> bool {
        self.session.lock().unwrap_or_else(|e| e.into_inner()).is_some()
            && self.transport().is_ok_and(|transport| transport.is_authed())
            && self
                .ack_channel
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some_and(|channel| !channel.closed.load(Ordering::Acquire))
    }

    pub fn magic1(&self) -> PResult<Vec<u8>> {
        Ok(self.transport()?.magic1())
    }

    pub fn magic2(&self) -> PResult<Vec<u8>> {
        Ok(self.transport()?.magic2())
    }
}


impl Drop for ProtocolClient {
    fn drop(&mut self) {
        self.close();
    }
}

struct HandshakeChannel {
    send_counter: u64,
    receive_counter: u64,
}
impl HandshakeChannel {
    fn new() -> Self {
        Self {
            send_counter: 0,
            receive_counter: 0,
        }
    }
}

fn hs_encrypt(counter: u64, key: &[u8], direction: u8, data: &[u8]) -> PResult<Vec<u8>> {
    let counter_bytes = counter.to_be_bytes();
    let mut aad = counter_bytes.to_vec();
    aad.push(direction);
    let encrypted = crypto::encrypt_gcm(data, key, Some(&aad))?;
    let mut payload = counter_bytes.to_vec();
    payload.extend_from_slice(&encrypted);
    Ok(payload)
}

fn hs_decrypt(
    blob: &[u8],
    key: &[u8],
    direction: u8,
    last_counter: &mut u64,
) -> PResult<Vec<u8>> {
    if blob.len() < 8 + crypto::AES_GCM_OVERHEAD {
        return Err(ProtocolFailure("encrypted handshake frame is too short".into()));
    }
    let counter_bytes: [u8; 8] = blob[..8].try_into().expect("8-byte counter");
    let counter = u64::from_be_bytes(counter_bytes);
    if counter != last_counter.saturating_add(1) {
        return Err(ProtocolFailure("handshake counter error".into()));
    }
    let mut aad = counter_bytes.to_vec();
    aad.push(direction);
    let plaintext = crypto::decrypt_gcm(&blob[8..], key, Some(&aad))?;
    *last_counter = counter;
    Ok(plaintext)
}

fn hs_send(
    transport: &transport::TransportServer,
    temp_cid: &[u8],
    key: &[u8],
    counter: &mut u64,
    direction: u8,
    data: &[u8],
) -> PResult<()> {
    *counter += 1;
    transport.send_handshake(temp_cid, hs_encrypt(*counter, key, direction, data)?)?;
    Ok(())
}

fn hs_recv(
    transport: &transport::TransportServer,
    temp_cid: &[u8],
    key: &[u8],
    counter: &mut u64,
    direction: u8,
    timeout: Duration,
) -> PResult<Vec<u8>> {
    let blob = recv_handshake_required(transport, temp_cid, timeout, "encrypted handshake message")?;
    hs_decrypt(&blob, key, direction, counter)
}

fn hs_send_client(
    transport: &transport::TransportClient,
    key: &[u8],
    counter: &mut u64,
    direction: u8,
    data: &[u8],
) -> PResult<()> {
    *counter += 1;
    transport.send_handshake(hs_encrypt(*counter, key, direction, data)?)?;
    Ok(())
}

fn hs_recv_client(
    transport: &transport::TransportClient,
    key: &[u8],
    counter: &mut u64,
    direction: u8,
    timeout: Duration,
) -> PResult<Vec<u8>> {
    let blob = recv_client_handshake_required(transport, timeout, "encrypted handshake message")?;
    hs_decrypt(&blob, key, direction, counter)
}

fn recv_handshake_required(
    transport: &transport::TransportServer,
    temp_cid: &[u8],
    timeout: Duration,
    what: &str,
) -> PResult<Vec<u8>> {
    transport
        .recv_handshake(temp_cid, Some(timeout))?
        .ok_or_else(|| ProtocolFailure(format!("timed out waiting for {what}")))
}

fn recv_client_handshake_required(
    transport: &transport::TransportClient,
    timeout: Duration,
    what: &str,
) -> PResult<Vec<u8>> {
    transport
        .recv_handshake(Some(timeout))?
        .ok_or_else(|| ProtocolFailure(format!("timed out waiting for {what}")))
}

fn exact_eid(value: &[u8]) -> PResult<[u8; 8]> {
    if value.len() != 8 {
        return Err(ProtocolFailure("eid must be exactly 8 bytes".into()));
    }
    let mut output = [0u8; 8];
    output.copy_from_slice(value);
    Ok(output)
}

fn ct_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn initialize_server_storage(password: &str, new_totp: bool) -> PResult<ServerStorage> {
    fs::create_dir_all(SERVER_DIR)?;
    fs::create_dir_all(AUTH_DIR)?;
    let salt_path = Path::new(SERVER_DIR).join(SERVER_SALT_FILE);
    let salt = if salt_path.exists() {
        let value = fs::read(&salt_path)?;
        if value.len() != crypto::SALT_SIZE {
            return Err(ProtocolFailure("SERVER SALT must be exactly 64 bytes".into()));
        }
        value
    } else {
        let value = crypto::gen_salt()?;
        write_atomic(&salt_path, &value)?;
        value
    };
    let at_rest_key = crypto::derive_at_rest_key(password, &salt)?;

    let signing_path = Path::new(SERVER_DIR).join(SERVER_SIGNING_FILE);
    let signing_private = if signing_path.exists() {
        let encrypted = fs::read(&signing_path)?;
        let private = crypto::decrypt_gcm(&encrypted, &at_rest_key, None)
            .map_err(|_| ProtocolFailure("could not decrypt server signing key; refusing to reset identity".into()))?;
        crypto::parse_framed_key(
            &private,
            Some(crypto::KeyKind::Ed448),
            Some(true),
        )?;
        private
    } else {
        let (private, _) = crypto::generate_keypair(crypto::KeyKind::Ed448)?;
        let encrypted = crypto::encrypt_gcm(&private, &at_rest_key, None)?;
        write_atomic(&signing_path, &encrypted)?;
        private
    };
    let signing_public = crypto::get_pub(&signing_private)?;

    let admin_totp_path = Path::new(SERVER_DIR).join(ADMIN_TOTP_FILE);
    let (admin_totp, print_totp) = if admin_totp_path.exists() && !new_totp {
        let encrypted = fs::read(&admin_totp_path)?;
        let secret = crypto::decrypt_gcm(&encrypted, &at_rest_key, None)
            .map_err(|_| ProtocolFailure("could not decrypt admin TOTP secret".into()))?;
        (secret, false)
    } else {
        let secret = crypto::random_bytes(20)?;
        let encrypted = crypto::encrypt_gcm(&secret, &at_rest_key, None)?;
        write_atomic(&admin_totp_path, &encrypted)?;
        (secret, true)
    };
    let bootstrap_path = Path::new(SERVER_DIR).join(BOOTSTRAP_TOTP_FILE);
    let bootstrap_totp = if bootstrap_path.exists() {
        let encrypted = fs::read(&bootstrap_path)?;
        Some(
            crypto::decrypt_gcm(&encrypted, &at_rest_key, None)
                .map_err(|_| ProtocolFailure("could not decrypt bootstrap TOTP secret".into()))?,
        )
    } else {
        None
    };
    if print_totp {
        println!("Admin TOTP secret: {}", crypto::totp_secret_string(&admin_totp));
        let cert = hex::encode(&signing_public);
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(30));
            print!("\x1b[2J\x1b[H");
            println!("Server certificate: {cert}");
        });
    }
    Ok(ServerStorage {
        at_rest_key,
        signing_private,
        signing_public,
        admin_totp,
        bootstrap_totp,
    })
}

fn prepare_client_identity(password: &str) -> PResult<ClientIdentity> {
    fs::create_dir_all(CLIENT_DIR)?;
    let salt_path = Path::new(CLIENT_DIR).join(CLIENT_SALT_FILE);
    let auth_path = Path::new(CLIENT_DIR).join(CLIENT_AUTH_FILE);
    let cert_path = Path::new(CLIENT_DIR).join(CLIENT_SERVER_CERT_FILE);
    let mut salt = if salt_path.exists() {
        fs::read(&salt_path)?
    } else {
        Vec::new()
    };
    if salt.len() != crypto::SALT_SIZE {
        let _ = fs::remove_file(&auth_path);
        let _ = fs::remove_file(&cert_path);
        salt = crypto::gen_salt()?;
        write_atomic(&salt_path, &salt)?;
    }
    let at_rest_key = crypto::derive_at_rest_key(password, &salt)?;
    let (signing_private, signing_public, server_cert, bootstrap_code) = if auth_path.exists() {
        let encrypted = fs::read(&auth_path)?;
        let private = crypto::decrypt_gcm(&encrypted, &at_rest_key, None)
            .map_err(|_| ProtocolFailure("could not decrypt client auth key".into()))?;
        crypto::parse_framed_key(
            &private,
            Some(crypto::KeyKind::Ed448),
            Some(true),
        )?;
        let public = crypto::get_pub(&private)?;
        let cert = if cert_path.exists() {
            let signed_cert = fs::read(&cert_path)?;
            let cert = crypto::ed25519_verify(&public, &signed_cert)
                .map_err(|_| ProtocolFailure("client server certificate pin is invalid".into()))?;
            crypto::parse_framed_key(
                &cert,
                Some(crypto::KeyKind::Ed448),
                Some(false),
            )?;
            Some(cert)
        } else {
            None
        };
        (private, public, cert, None)
    } else {
        let (private, public) = crypto::generate_keypair(crypto::KeyKind::Ed448)?;
        let code = prompt_line("Auth Key Security Code: ")?;
        if code.trim().is_empty() {
            return Err(ProtocolFailure("bootstrap security code cannot be empty".into()));
        }
        (private, public, None, Some(code.trim().to_string()))
    };
    Ok(ClientIdentity {
        salt,
        at_rest_key,
        signing_private,
        signing_public,
        server_cert,
        bootstrap_code,
    })
}

fn prompt_line(prompt: &str) -> PResult<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim_end_matches(|c| c == '\r' || c == '\n').to_string())
}

fn write_atomic(path: &Path, contents: &[u8]) -> PResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| ProtocolFailure("path has no parent".into()))?;
    fs::create_dir_all(parent)?;
    let nonce = crypto::random_hex_id(8)?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("network2-data");
    let temporary = parent.join(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = replace_file(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}


#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

fn print_server_identity(public: &[u8]) {
    println!("Server certificate: {}", hex::encode(public));
}

fn valid_username(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|value| value.is_ascii_alphanumeric() || matches!(*value, b'_' | b'.' | b'-'))
}

fn validate_stored_username(name: &str) -> PResult<String> {
    let basename = Path::new(name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let stem = Path::new(basename)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let bytes = stem.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|value| value.is_ascii_alphanumeric() || matches!(*value, b'_' | b'.' | b'-'))
    {
        return Err(ProtocolFailure("invalid stored username".into()));
    }
    Ok(stem.to_string())
}