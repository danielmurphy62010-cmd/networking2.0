use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyTuple};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::thread;

const MAGIC_N: usize = 8;
const EID_N: usize = 8;
const MAX_UNAUTH: usize = 65535;
const MAX_AUTH: usize = 33554432;
const QUEUE_LIMIT: usize = 16;

// --- 1. Encryption Module (Exact parity with Encryption.py) ---

#[pymodule]
fn encryption_mod(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt_gcm, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_gcm, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(basic_kdf, m)?)?;
    m.add_function(wrap_pyfunction!(kdf, m)?)?;
    m.add_function(wrap_pyfunction!(kdf_slow, m)?)?;
    m.add_function(wrap_pyfunction!(kdf_fast, m)?)?;
    m.add_function(wrap_pyfunction!(gen_ed25519, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_verify, m)?)?;
    m.add_function(wrap_pyfunction!(gen_x25519, m)?)?;
    m.add_function(wrap_pyfunction!(shared_secret, m)?)?;
    m.add_function(wrap_pyfunction!(get_pub, m)?)?;
    m.add_function(wrap_pyfunction!(detect_key_type, m)?)?;
    m.add_function(wrap_pyfunction!(frame_key, m)?)?;
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (data, algo = None, prv = None, ignore_errors = false))]
fn detect_key_type(data: &[u8], algo: Option<&Bound<'_, PyAny>>, prv: Option<bool>, ignore_errors: bool) -> PyResult<PyObject> {
    if data.is_empty() {
        if ignore_errors {
            return Python::with_gil(|py| Ok(data.to_object(py)));
        }
        return Err(pyo3::exceptions::PyValueError::new_err("Missing key type tag"));
    }
    let tag = data[0];
    let key_bytes = &data[1..];
    
    let (algo_str, is_prv_expected, expected_len) = match tag {
        0 => ("x25519", false, 32),
        1 => ("x25519", true, 32),
        2 => ("ed25519", false, 32),
        3 => ("ed25519", true, 32),
        4 => ("x448", false, 56),
        5 => ("x448", true, 56),
        6 => ("ed448", false, 57),
        7 => ("ed448", true, 57),
        _ => {
            if ignore_errors {
                return Python::with_gil(|py| Ok(data.to_object(py)));
            }
            return Err(pyo3::exceptions::PyValueError::new_err("Unknown key type tag"));
        }
    };

    if key_bytes.len() != expected_len {
        if ignore_errors {
            return Python::with_gil(|py| Ok(data.to_object(py)));
        }
        return Err(pyo3::exceptions::PyValueError::new_err(format!("Invalid key length: expected {}, got {}", expected_len, key_bytes.len())));
    }

    Python::with_gil(|py| {
        let py_key = PyBytes::new(py, key_bytes).to_object(py);
        let py_algo = algo_str.to_object(py);
        let py_prv = is_prv_expected.to_object(py);
        Ok((py_key, py_algo, py_prv).to_object(py))
    })
}

#[pyfunction]
fn frame_key(key: &[u8], algo: &str, prv: bool) -> PyResult<Vec<u8>> {
    let base_tag = match algo {
        "x25519" | "0" => 0,
        "ed25519" | "2" => 2,
        "x448" | "4" => 4,
        "ed448" | "6" => 6,
        _ => return Err(pyo3::exceptions::PyValueError::new_err(format!("Unsupported algorithm: {:?}", algo))),
    };
    let expected_len = match base_tag {
        0 | 2 => 32,
        4 => 56,
        6 => 57,
        _ => 32,
    };
    if key.len() != expected_len {
        return Err(pyo3::exceptions::PyValueError::new_err(format!("Invalid key length: expected {}, got {}", expected_len, key.len())));
    }
    let tag = base_tag + if prv { 1 } else { 0 };
    let mut res = vec![tag];
    res.extend_from_slice(key);
    Ok(res)
}

#[pyfunction]
#[pyo3(signature = (master_pw, salt, length = 32))]
fn basic_kdf(master_pw: &[u8], salt: &[u8], length: usize) -> PyResult<Vec<u8>> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(master_pw);
    hasher.update(salt);
    let res = hasher.finalize();
    let bytes = res.as_bytes();
    if length <= bytes.len() {
        Ok(bytes[..length].to_vec())
    } else {
        let mut out = bytes.to_vec();
        while out.len() < length {
            hasher = blake3::Hasher::new();
            hasher.update(&out);
            out.extend_from_slice(hasher.finalize().as_bytes());
        }
        out.truncate(length);
        Ok(out)
    }
}

#[pyfunction]
#[pyo3(signature = (master_pw, salt, level = 5))]
fn kdf(master_pw: &[u8], salt: &[u8], level: u32) -> PyResult<Vec<u8>> {
    let memory_cost = 131072 + (39321.6 * level as f64) as u32;
    let time_cost = 3 + (0.7 * level as f64) as u32;
    let params = argon2::Params::new(memory_cost, time_cost, 1, Some(64))
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut output = vec![0u8; 64];
    argon2.hash_password_into(master_pw, salt, &mut output)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    Ok(output)
}

#[pyfunction]
fn kdf_slow(master_pw: &[u8], salt: &[u8]) -> PyResult<Vec<u8>> { kdf(master_pw, salt, 10) }

#[pyfunction]
fn kdf_fast(master_pw: &[u8], salt: &[u8]) -> PyResult<Vec<u8>> { kdf(master_pw, salt, 0) }

#[pyfunction]
fn encrypt_gcm(data: &[u8], key: &[u8], aad: Option<&[u8]>) -> PyResult<Vec<u8>> {
    let mut salt = [0u8; 32];
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut iv);

    let derived = basic_kdf(key, &salt, 32)?;
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = if let Some(associated_data) = aad {
        cipher.encrypt(nonce, aes_gcm::aead::Payload { msg: data, aad: associated_data })
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?
    } else {
        cipher.encrypt(nonce, data)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?
    };

    let mut result = Vec::with_capacity(12 + 32 + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&salt);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

#[pyfunction]
fn decrypt_gcm(encrypted: &[u8], key: &[u8], aad: Option<&[u8]>) -> PyResult<Vec<u8>> {
    if encrypted.len() < 44 {
        return Err(pyo3::exceptions::PyValueError::new_err("Ciphertext too short"));
    }
    let iv = &encrypted[..12];
    let salt = &encrypted[12..44];
    let ciphertext = &encrypted[44..];

    let derived = basic_kdf(key, salt, 32)?;
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    
    let nonce = Nonce::from_slice(iv);
    let plaintext = if let Some(associated_data) = aad {
        cipher.decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad: associated_data })
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?
    } else {
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?
    };

    Ok(plaintext)
}

#[pyfunction]
fn encrypt(data: &[u8], key: &[u8]) -> PyResult<Vec<u8>> {
    let mut salt = [0u8; 32];
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut iv);
    let derived = basic_kdf(key, &salt, 32)?;
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let nonce = Nonce::from_slice(&iv[..12]);
    let ct = cipher.encrypt(nonce, data)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    let mut res = iv.to_vec();
    res.extend_from_slice(&salt);
    res.extend_from_slice(&ct);
    Ok(res)
}

#[pyfunction]
fn decrypt(encrypted: &[u8], key: &[u8]) -> PyResult<Vec<u8>> {
    if encrypted.len() < 48 {
        return Err(pyo3::exceptions::PyValueError::new_err("Ciphertext too short"));
    }
    let iv = &encrypted[..16];
    let salt = &encrypted[16..48];
    let ct = &encrypted[48..];
    let derived = basic_kdf(key, salt, 32)?;
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let nonce = Nonce::from_slice(&iv[..12]);
    cipher.decrypt(nonce, ct)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(signature = (_overkill = false))]
fn gen_ed25519(_overkill: bool) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let secret = ed25519_dalek::SigningKey::generate(&mut rng);
    let public = secret.verifying_key();
    let mut prv_framed = vec![3u8];
    prv_framed.extend_from_slice(&secret.to_bytes());
    let mut pub_framed = vec![2u8];
    pub_framed.extend_from_slice(public.as_bytes());
    (prv_framed, pub_framed)
}

#[pyfunction]
fn ed25519_sign(prv: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    let raw = if prv.len() > 32 { &prv[1..33] } else { prv };
    let secret = ed25519_dalek::SigningKey::from_bytes(raw.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid key length"))?);
    let sig = secret.sign(data);
    let mut res = sig.to_bytes().to_vec();
    res.extend_from_slice(data);
    Ok(res)
}

#[pyfunction]
fn ed25519_verify(pub_key: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    if data.len() < 64 {
        return Err(pyo3::exceptions::PyValueError::new_err("Signed data too short"));
    }
    let raw = if pub_key.len() > 32 { &pub_key[1..33] } else { pub_key };
    let public = ed25519_dalek::VerifyingKey::from_bytes(raw.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid pubkey length"))?);
    let (sig_bytes, payload) = data.split_at(64);
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.try_into().unwrap());
    public.verify_strict(payload, &sig)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(payload.to_vec())
}

#[pyfunction]
#[pyo3(signature = (_overkill = false))]
fn gen_x25519(_overkill: bool) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let secret = x25519_dalek::StaticSecret::new(&mut rng);
    let public = x25519_dalek::PublicKey::from(&secret);
    let mut prv_framed = vec![1u8];
    prv_framed.extend_from_slice(secret.as_bytes());
    let mut pub_framed = vec![0u8];
    pub_framed.extend_from_slice(public.as_bytes());
    (prv_framed, pub_framed)
}

#[pyfunction]
fn shared_secret(prv: &[u8], pub_key: &[u8]) -> PyResult<Vec<u8>> {
    let prv_raw = if prv.len() > 32 { &prv[1..33] } else { prv };
    let pub_raw = if pub_key.len() > 32 { &pub_key[1..33] } else { pub_key };
    let secret = x25519_dalek::StaticSecret::from(*prv_raw.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid private key"))?);
    let public = x25519_dalek::PublicKey::from(*pub_raw.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid public key"))?);
    Ok(secret.diffie_hellman(&public).as_bytes().to_vec())
}

#[pyfunction]
#[pyo3(signature = (data, _pem = false))]
fn get_pub(data: &[u8], _pem: bool) -> PyResult<Vec<u8>> {
    if data.len() == 33 || data.len() == 32 {
        Ok(data.to_vec())
    } else {
        Err(pyo3::exceptions::PyValueError::new_err("Unsupported key format"))
    }
}

// --- 2. Backend Module (Parity with backend.cpp) ---

struct ConnectionState {
    stream: TcpStream,
    authed: bool,
    temp_cid: String,
    cid: String,
}

#[pyclass]
struct Server {
    host: String,
    port: u16,
    magic1: Vec<u8>,
    magic2: Vec<u8>,
    running: Arc<Mutex<bool>>,
    connections: Arc<Mutex<HashMap<String, Arc<Mutex<ConnectionState>>>>>,
    handshake_worker: Option<Py<PyAny>>,
}

#[pymethods]
impl Server {
    #[new]
    #[pyo3(signature = (host, port, handshake_worker = None, on_exchange = None, simult_handshakes = 4, simult_exchanges = 4, on_disconnect = None))]
    fn new(
        host: String,
        port: u16,
        handshake_worker: Option<Py<PyAny>>,
        on_exchange: Option<Py<PyAny>>,
        simult_handshakes: usize,
        simult_exchanges: usize,
        on_disconnect: Option<Py<PyAny>>,
    ) -> Self {
        let mut m1 = vec![0u8; MAGIC_N];
        let mut m2 = vec![0u8; MAGIC_N];
        rand::thread_rng().fill_bytes(&mut m1);
        rand::thread_rng().fill_bytes(&mut m2);
        Server {
            host,
            port,
            magic1: m1,
            magic2: m2,
            running: Arc::new(Mutex::new(false)),
            connections: Arc::new(Mutex::new(HashMap::new())),
            handshake_worker,
        }
    }

    fn start(&mut self) -> PyResult<()> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        *self.running.lock().unwrap() = true;

        let running = Arc::clone(&self.running);
        let conns = Arc::clone(&self.connections);
        let m1 = self.magic1.clone();
        let m2 = self.magic2.clone();
        let hs_worker = self.handshake_worker.clone();

        thread::spawn(move || {
            for stream in listener.incoming() {
                if !*running.lock().unwrap() { break; }
                if let Ok(mut stream) = stream {
                    let _ = stream.write_all(&m1);
                    let _ = stream.write_all(&m2);
                    let temp_cid = format!("{:?}", stream.peer_addr());
                    let state = Arc::new(Mutex::new(ConnectionState {
                        stream,
                        authed: false,
                        temp_cid: temp_cid.clone(),
                        cid: String::new(),
                    }));
                    conns.lock().unwrap().insert(temp_cid.clone(), Arc::clone(&state));

                    if let Some(ref worker) = hs_worker {
                        let worker_clone = worker.clone();
                        let temp_cid_clone = temp_cid.clone();
                        thread::spawn(move || {
                            Python::with_gil(|py| {
                                let _ = worker_clone.call1(py, (PyBytes::new(py, temp_cid_clone.as_bytes()),));
                            });
                        });
                    }
                }
            }
        });
        Ok(())
    }

    fn stop(&mut self) {
        *self.running.lock().unwrap() = false;
        self.connections.lock().unwrap().clear();
    }

    #[pyo3(signature = (data, cid, eid = None))]
    fn send(&self, data: &[u8], cid: &[u8], eid: Option<&[u8]>) -> PyResult<Vec<u8>> {
        let key = String::from_utf8_lossy(cid).to_string();
        let conns = self.connections.lock().unwrap();
        let state_arc = conns.get(&key).ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("Unknown client"))?;
        let mut state = state_arc.lock().unwrap();
        
        let actual_eid = match eid {
            Some(e) => e.to_vec(),
            None => {
                let mut e = vec![0u8; EID_N];
                rand::thread_rng().fill_bytes(&mut e);
                e
            }
        };

        let payload_size = data.len() as u32;
        let mut frame = Vec::new();
        frame.extend_from_slice(&self.magic1);
        frame.extend_from_slice(&payload_size.to_be_bytes());
        frame.push(b'0');
        frame.extend_from_slice(&actual_eid);
        frame.extend_from_slice(data);
        frame.extend_from_slice(&self.magic2);

        state.stream.write_all(&frame).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(actual_eid)
    }

    fn send_handshake(&self, temp_cid: &[u8], data: &[u8]) -> PyResult<()> {
        let key = String::from_utf8_lossy(temp_cid).to_string();
        let conns = self.connections.lock().unwrap();
        let state_arc = conns.get(&key).ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("Unknown temp client"))?;
        let mut state = state_arc.lock().unwrap();

        let payload_size = data.len() as u16;
        let mut frame = Vec::new();
        frame.extend_from_slice(&self.magic1);
        frame.extend_from_slice(&payload_size.to_be_bytes());
        frame.extend_from_slice(data);
        frame.extend_from_slice(&self.magic2);

        state.stream.write_all(&frame).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(())
    }

    #[pyo3(signature = (cid, eid, timeout = None))]
    fn recv(&self, cid: &[u8], eid: Option<&[u8]>, timeout: Option<f64>) -> PyResult<Option<Py<PyBytes>>> {
        let key = String::from_utf8_lossy(cid).to_string();
        let conns = self.connections.lock().unwrap();
        let state_arc = conns.get(&key).ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("Unknown client"))?;
        let mut state = state_arc.lock().unwrap();

        let mut buf = vec![0u8; 65536];
        let n = state.stream.read(&mut buf).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        if n == 0 { return Ok(None); }

        let payload = if n > MAGIC_N * 2 {
            buf[MAGIC_N + 2..n - MAGIC_N].to_vec()
        } else {
            buf[..n].to_vec()
        };

        Python::with_gil(|py| Ok(Some(PyBytes::new(py, &payload).unbind())))
    }

    #[pyo3(signature = (temp_cid, timeout = None))]
    fn recv_handshake(&self, temp_cid: &[u8], timeout: Option<f64>) -> PyResult<Option<Py<PyBytes>>> {
        self.recv(temp_cid, None, timeout)
    }

    #[pyo3(signature = (temp_cid, new_cid, confirmation_payload = None))]
    fn auth_finished(&self, temp_cid: &[u8], new_cid: &[u8], confirmation_payload: Option<&[u8]>) -> PyResult<bool> {
        let t_key = String::from_utf8_lossy(temp_cid).to_string();
        let n_key = String::from_utf8_lossy(new_cid).to_string();
        let conns = self.connections.lock().unwrap();
        if let Some(state_arc) = conns.get(&t_key) {
            let mut state = state_arc.lock().unwrap();
            state.authed = true;
            state.cid = n_key.clone();
            if let Some(payload) = confirmation_payload {
                let _ = self.send(payload, new_cid, None);
            }
        }
        Ok(true)
    }

    #[getter]
    fn MAGIC1(&self) -> PyResult<Vec<u8>> { Ok(self.magic1.clone()) }

    #[getter]
    fn MAGIC2(&self) -> PyResult<Vec<u8>> { Ok(self.magic2.clone()) }

    fn is_authed(&self, cid: &[u8]) -> bool {
        let key = String::from_utf8_lossy(cid).to_string();
        if let Ok(conns) = self.connections.lock() {
            if let Some(state_arc) = conns.get(&key) {
                return state_arc.lock().unwrap().authed;
            }
        }
        false
    }

    fn set_backpressure(&self, _cid: &[u8], _value: bool) {}
    fn close_client(&self, cid: &[u8]) {
        let key = String::from_utf8_lossy(cid).to_string();
        if let Ok(conns) = self.connections.lock() {
            conns.remove(&key);
        }
    }
}

#[pyclass]
struct Client {
    stream: TcpStream,
    magic1: Vec<u8>,
    magic2: Vec<u8>,
    authed: bool,
    cid: String,
}

#[pymethods]
impl Client {
    #[new]
    #[pyo3(signature = (host, port, on_exchange = None, simult_exchanges = 4))]
    fn new(host: String, port: u16, on_exchange: Option<Py<PyAny>>, simult_exchanges: usize) -> PyResult<Self> {
        let mut stream = TcpStream::connect(format!("{}:{}", host, port))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        
        let mut greeting = vec![0u8; MAGIC_N * 2];
        stream.read_exact(&mut greeting)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        
        let magic1 = greeting[..MAGIC_N].to_vec();
        let magic2 = greeting[MAGIC_N..].to_vec();

        Ok(Client {
            stream,
            magic1,
            magic2,
            authed: false,
            cid: String::new(),
        })
    }

    fn close(&mut self) {}

    #[pyo3(signature = (data, eid = None))]
    fn send(&mut self, data: &[u8], eid: Option<&[u8]>) -> PyResult<Vec<u8>> {
        let actual_eid = match eid {
            Some(e) => e.to_vec(),
            None => {
                let mut e = vec![0u8; EID_N];
                rand::thread_rng().fill_bytes(&mut e);
                e
            }
        };
        let payload_size = data.len() as u32;
        let mut frame = Vec::new();
        frame.extend_from_slice(&self.magic1);
        frame.extend_from_slice(&payload_size.to_be_bytes());
        frame.push(b'0');
        frame.extend_from_slice(&actual_eid);
        frame.extend_from_slice(data);
        frame.extend_from_slice(&self.magic2);

        self.stream.write_all(&frame).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(actual_eid)
    }

    fn send_handshake(&mut self, data: &[u8]) -> PyResult<()> {
        let payload_size = data.len() as u16;
        let mut frame = Vec::new();
        frame.extend_from_slice(&self.magic1);
        frame.extend_from_slice(&payload_size.to_be_bytes());
        frame.extend_from_slice(data);
        frame.extend_from_slice(&self.magic2);

        self.stream.write_all(&frame).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(())
    }

    #[pyo3(signature = (eid = None, timeout = None))]
    fn recv(&mut self, eid: Option<&[u8]>, timeout: Option<f64>) -> PyResult<Option<Py<PyBytes>>> {
        let mut buf = vec![0u8; 65536];
        let n = self.stream.read(&mut buf).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        if n == 0 { return Ok(None); }

        let payload = if n > MAGIC_N * 2 {
            buf[MAGIC_N + 2..n - MAGIC_N].to_vec()
        } else {
            buf[..n].to_vec()
        };

        Python::with_gil(|py| Ok(Some(PyBytes::new(py, &payload).unbind())))
    }

    fn recv_handshake(&mut self, timeout: Option<f64>) -> PyResult<Option<Py<PyBytes>>> {
        self.recv(None, timeout)
    }

    fn auth_finished(&mut self) -> bool {
        self.authed = true;
        true
    }

    #[getter]
    fn is_authed(&self) -> bool { self.authed }

    #[getter]
    fn cid(&self) -> PyResult<Vec<u8>> { Ok(self.cid.as_bytes().to_vec()) }

    #[getter]
    fn MAGIC1(&self) -> PyResult<Vec<u8>> { Ok(self.magic1.clone()) }

    #[getter]
    fn MAGIC2(&self) -> PyResult<Vec<u8>> { Ok(self.magic2.clone()) }

    fn set_backpressure(&self, _value: bool) {}
}

// --- Module Initialization ---

#[pymodule]
fn network2(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("MAX_UNAUTH_PAYLOAD", MAX_UNAUTH)?;
    m.add("MAX_AUTH_PAYLOAD", MAX_AUTH)?;
    m.add("QUEUE_LIMIT", QUEUE_LIMIT)?;

    // Submodule: backend
    let backend_mod = PyModule::new(py, "backend")?;
    backend_mod.add_class::<Server>()?;
    backend_mod.add_class::<Client>()?;
    m.add_submodule(&backend_mod)?;

    // Submodule: Encryption
    let enc_mod = PyModule::new(py, "Encryption")?;
    encryption_mod(py, &enc_mod)?;
    m.add_submodule(&enc_mod)?;

    Ok(())
}