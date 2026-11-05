pub mod backend;
pub mod Encryption;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::runtime::Runtime;
use totp_rs::{Secret, TOTP, Algorithm as TotpAlgorithm};
use hex;
pub const SALT_SIZE: usize = 64;
pub const MAX_TIMEOUT: u64 = 10;
pub const EID_SIZE: usize = 8;
#[pyclass]
#[derive(Debug, Clone)]
pub struct ProtocolError {
    #[pyo3(get)]
    message: String,
}
impl From<ProtocolError> for PyErr {
    fn from(err: ProtocolError) -> Self {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(err.message)
    }
}
#[pymethods]
impl ProtocolError {
    #[new]
    fn new(message: String) -> Self {
        Self { message }
    }
    
    fn __str__(&self) -> String {
        format!("ProtocolError: {}", self.message)
    }
}
impl From<String> for ProtocolError {
    fn from(message: String) -> Self {
        Self { message }
    }
}
impl From<backend::BackendError> for ProtocolError {
    fn from(err: backend::BackendError) -> Self {
        Self { message: err.to_string() }
    }
}
fn new_eid() -> Result<[u8; EID_SIZE], ProtocolError> {
    let mut bytes = [0u8; EID_SIZE];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    Ok(bytes)
}
fn derive_at_rest_key(password: &str, salt_path: &str) -> Result<Vec<u8>, ProtocolError> {
    if password.is_empty() {
        return Err(ProtocolError::new("Password cannot be empty.".into()));
    }
    let z_res = zxcvbn::zxcvbn(password, &[]);
    let guesses_log10 = z_res?.guesses_log10();
    if guesses_log10 <= 9.0 {
        return Err(ProtocolError::new(format!(
            "Password too weak (log10 guesses: {:.2}). Must be > 9.",
            guesses_log10
        )));
    }
    let salt = if Path::new(salt_path).exists() {
        let s = fs::read(salt_path).map_err(|e| ProtocolError::new(e.to_string()))?;
        if s.len() != SALT_SIZE {
            return Err(ProtocolError::new(format!("Salt file must contain exactly {} bytes.", SALT_SIZE)));
        }
        s
    } else {
        if let Some(parent) = Path::new(salt_path).parent() {
            fs::create_dir_all(parent).map_err(|e| ProtocolError::new(e.to_string()))?;
        }
        let mut s = vec![0u8; SALT_SIZE];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut s);
        fs::write(salt_path, &s).map_err(|e| ProtocolError::new(e.to_string()))?;
        s
    };
    Encryption::kdf_slow(password.as_bytes(), &salt)
        .map_err(|e| ProtocolError::new(e.to_string()))
}
#[pyclass]
pub struct TCPServer {
    rt: Runtime,
    server: Arc<backend::Server>,
    at_rest_key: Vec<u8>,
    signing_keys: (Vec<u8>, Vec<u8>),
    enable_bootstrap: Arc<Mutex<bool>>,
    keys: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    counters: Arc<Mutex<HashMap<Vec<u8>, [u64; 2]>>>,
    admin: Arc<Mutex<HashMap<Vec<u8>, bool>>>,
    usernames: Arc<Mutex<HashMap<Vec<u8>, String>>>,
    pending_bootstrap_totp: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    admin_totp_path: String,
    bootstrap_totp_path: String,
}
#[pymethods]
impl TCPServer {
    #[new]
    #[pyo3(signature = (host, port, password, new_totp=false, on_exchange=None, simult_exchanges=4))]
    fn new(
        host: String,
        port: u16,
        password: String,
        new_totp: bool,
        on_exchange: Option<PyObject>,
        simult_exchanges: usize,
    ) -> PyResult<Self> {
        let rt = Runtime::new().map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        fs::create_dir_all("./auth keys").map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
        fs::create_dir_all("./server keys").map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
        let salt_path = "./server keys/SERVER SALT";
        let at_rest_key = derive_at_rest_key(&password, salt_path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.message))?;
        let sig_key_path = "./server keys/SIGNING KEY";
        let admin_totp_path = "./server keys/ADMIN - TOTP".to_string();
        let bootstrap_totp_path = "./server keys/BOOTSTRAP - TOTP".to_string();
        let mut reset = false;
        for path in &[sig_key_path, &admin_totp_path] {
            if let Ok(data) = fs::read(path) {
                if Encryption::decryptGCM(&data, &at_rest_key, None).is_err() {
                    reset = true;
                }
            } else {
                reset = true;
            }
        }
        if reset {
            let _ = fs::remove_dir_all("./auth keys");
            let _ = fs::remove_dir_all("./server keys");
            fs::create_dir_all("./auth keys").ok();
            fs::create_dir_all("./server keys").ok();
        }
        let signing_keys = if Path::new(sig_key_path).exists() {
            let encrypted = fs::read(sig_key_path).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
            let prv = Encryption::decryptGCM(&encrypted, &at_rest_key, None)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            let pub_k = Encryption::get_pub(&prv, false)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            (prv, pub_k)
        } else {
            let keys = Encryption::gen_ed25519(true)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            let encrypted = Encryption::encryptGCM(&keys.0, &at_rest_key, None)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            fs::write(sig_key_path, encrypted).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
            (keys.0, keys.1)
        };
        if new_totp || !Path::new(&admin_totp_path).exists() {
            let mut totp_bytes = [0u8; 20];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut totp_bytes);
            let base32_secret = base64::encode(&totp_bytes);
            let encrypted_totp = Encryption::encryptGCM(&totp_bytes, &at_rest_key, None)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            fs::write(&admin_totp_path, encrypted_totp).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
            println!("--- NEW TOTP SECRET (Base32): {} ---", base32_secret);
        }
        println!("Server Certificate: {}", hex::encode(&signing_keys.1));
        let enable_bootstrap = Arc::new(Mutex::new(false));
        let keys = Arc::new(Mutex::new(HashMap::new()));
        let counters = Arc::new(Mutex::new(HashMap::new()));
        let admin = Arc::new(Mutex::new(HashMap::new()));
        let usernames = Arc::new(Mutex::new(HashMap::new()));
        let pending_bootstrap_totp = Arc::new(Mutex::new(HashMap::new()));
        let signing_pub_clone = signing_keys.1.clone();
        let signing_prv_clone = signing_keys.0.clone();
        let at_rest_key_clone = at_rest_key.clone();
        let eb_clone = Arc::clone(&enable_bootstrap);
        let keys_clone = Arc::clone(&keys);
        let counters_clone = Arc::clone(&counters);
        let admin_clone = Arc::clone(&admin);
        let usernames_clone = Arc::clone(&usernames);
        let admin_totp_clone = admin_totp_path.clone();
        let bootstrap_totp_clone = bootstrap_totp_path.clone();
        let server_ref_for_hs = Arc::new(Mutex::new(None));
        let server_ref_clone = Arc::clone(&server_ref_for_hs);
        let handshake_worker: backend::HandshakeCallback = Arc::new(move |temp_cid: Vec<u8>| {
            let pub_key = signing_pub_clone.clone();
            let prv_key = signing_prv_clone.clone();
            let ark = at_rest_key_clone.clone();
            let eb = Arc::clone(&eb_clone);
            let keys_map = Arc::clone(&keys_clone);
            let counters_map = Arc::clone(&counters_clone);
            let admin_map = Arc::clone(&admin_clone);
            let usernames_map = Arc::clone(&usernames_clone);
            let admin_totp = admin_totp_clone.clone();
            let bootstrap_totp = bootstrap_totp_clone.clone();
            let s_ref = Arc::clone(&server_ref_clone);
            Box::pin(async move {
                let s_opt = s_ref.lock().unwrap().clone();
                let s = match s_opt {
                    Some(server_inst) => server_inst,
                    None => return,
                };
                let _ = s.send_handshake(&temp_cid, pub_key.clone());
                let client_pub_opt = s.recv_handshake(&temp_cid, Some(Duration::from_secs(1))).await;
                let client_pub = match client_pub_opt {
                    Ok(Some(cp)) => cp,
                    _ => return,
                };
                if client_pub.starts_with(b"REQ_ADMIN") {
                    let client_init_pub = client_pub[9..].to_vec();
                    let init_key = match Encryption::gen_x25519(true) {
                        Ok(k) => k,
                        Err(_) => return,
                    };
                    let tss = match Encryption::shared_secret(&init_key.0, &client_init_pub) {
                        Ok(t) => t,
                        Err(_) => return,
                    };
                    let mut sc: u64 = 1;
                    let mut rc: u64 = 0;
                    let mut ekey_defined = false;
                    let mut current_ekey = vec![];
                    let s_clone = Arc::clone(&s);
                    let tc_clone = temp_cid.clone();
                    let send_enc = move |data: &[u8], ekey: &[u8], defined: bool| -> Result<(), backend::BackendError> {
                        let ctr = sc.to_be_bytes();
                        sc += 1;
                        let mut aad = ctr.to_vec();
                        aad.extend_from_slice(b"1");
                        let target_key = if defined { ekey } else { &tss };
                        let encrypted = Encryption::encryptGCM(data, target_key, Some(&aad)).unwrap();
                        let mut payload = ctr.to_vec();
                        payload.extend_from_slice(&encrypted);
                        s_clone.send_handshake(&tc_clone, payload)
                    };
                    let s_clone2 = Arc::clone(&s);
                    let tc_clone2 = temp_cid.clone();
                    let mut recv_enc = move |timeout: u64, ekey: &[u8], defined: bool| -> Result<Vec<u8>, ProtocolError> {
                        let payload = tokio::task::block_in_place(|| {
                            rt_block_on(s_clone2.recv_handshake(&tc_clone2, Some(Duration::from_secs(timeout))))
                        }).map_err(|e| ProtocolError::new(e.to_string()))?.ok_or_else(|| ProtocolError::new("Timed out".into()))?;
                        if payload.len() < 8 {
                            return Err(ProtocolError::new("Timed out".into()));
                        }
                        let ctr = &payload[..8];
                        let counter = u64::from_be_bytes(ctr.try_into().unwrap());
                        if counter != rc + 1 {
                            return Err(ProtocolError::new("Counter Error".into()));
                        }
                        rc = counter;
                        let mut aad = ctr.to_vec();
                        aad.extend_from_slice(b"0");
                        let target_key = if defined { ekey } else { &tss };
                        let out = Encryption::decryptGCM(&payload[8..], target_key, Some(&aad))
                            .map_err(|e| ProtocolError::new(e.to_string()))?;
                        Ok(out)
                    };
                    let mut tss_salt = vec![0u8; 64];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut tss_salt);
                    let mut sign_data = init_key.1.clone();
                    sign_data.extend_from_slice(&tss_salt);
                    let signed_init = Encryption::ed25519_sign(&prv_key, &sign_data).unwrap();
                    let _ = s.send_handshake(&temp_cid, signed_init);
                    let admin_totp_bytes = fs::read(&admin_totp).ok().and_then(|d| Encryption::decryptGCM(&d, &ark, None).ok()).unwrap_or_default();
                    let base32_sec = base64::encode(&admin_totp_bytes);
                    let totp = TOTP::new(TotpAlgorithm::SHA1, 6, 1, 30, Secret::Encoded(base32_sec).to_bytes().unwrap()).unwrap();
                    let code = totp.generate_current().unwrap();
                    let mut kdf_input = code.as_bytes().to_vec();
                    kdf_input.extend_from_slice(&tss_salt);
                    kdf_input.extend_from_slice(&tss);
                    let admin_ekey = Encryption::kdf(&code.as_bytes(), &kdf_input, 5).unwrap_or(tss);
                    let mut nonce1 = vec![0u8; 32];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce1);
                    let _ = send_enc(&nonce1, &admin_ekey, true);
                    let nonce2 = match recv_enc(5, &admin_ekey, true) {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let mut nhash_input = nonce1.clone();
                    nhash_input.extend_from_slice(&nonce2);
                    let nhash = Encryption::basic_kdf(&nhash_input, b"", 64);
                    let client_nhash = match recv_enc(5, &admin_ekey, true) {
                        Ok(h) => h,
                        Err(_) => return,
                    };
                    if client_nhash != nhash {
                        return;
                    }
                    let _ = send_enc(&Encryption::basic_kdf(&nhash, b"", 64), &admin_ekey, true);
                    let _hash = temp_cid.clone();
                    keys_map.lock().unwrap().insert(_hash.clone(), admin_ekey);
                    counters_map.lock().unwrap().insert(_hash.clone(), [sc, rc]);
                    admin_map.lock().unwrap().insert(_hash.clone(), true);
                    let _ = s.auth_finished(&temp_cid, _hash, None);
                } else {
                    let mut auth_file = String::new();
                    if let Ok(entries) = fs::read_dir("./auth keys") {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if let Ok(stored_data) = fs::read(&path) {
                                if let Ok(stored_pub) = Encryption::ed25519_verify(&pub_key, &stored_data) {
                                    if subtle::ConstantTimeEq::ct_eq(&stored_pub, &client_pub).into() {
                                        auth_file = path.to_string_lossy().into_owned();
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if !auth_file.is_empty() {
                        let _ = s.send_handshake(&temp_cid, b"ACK".to_vec());
                        let keys = Encryption::gen_x25519(true).unwrap();
                        let signed_ephem = Encryption::ed25519_sign(&prv_key, &keys.1).unwrap();
                        let _ = s.send_handshake(&temp_cid, signed_ephem);
                        let signed_client_ephemeral = match s.recv_handshake(&temp_cid, Some(Duration::from_secs(5))).await {
                            Ok(Some(p)) => p,
                            _ => return,
                        };
                        let client_ephemeral_pub = match Encryption::ed25519_verify(&client_pub, &signed_client_ephemeral) {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        let ekey = Encryption::shared_secret(&keys.0, &client_ephemeral_pub).unwrap();
                        let _hash = Encryption::basic_kdf(&client_pub, b"", 6);
                        keys_map.lock().unwrap().insert(_hash.clone(), ekey);
                        counters_map.lock().unwrap().insert(_hash.clone(), [1, 0]);
                        admin_map.lock().unwrap().insert(_hash.clone(), false);
                        if let Some(fname) = Path::new(&auth_file).file_name().and_then(|n| n.to_str()) {
                            usernames_map.lock().unwrap().insert(_hash.clone(), fname.to_string());
                        }
                        let _ = s.auth_finished(&temp_cid, _hash, None);
                    } else {
                        let bootstrap_enabled = *eb.lock().unwrap();
                        if !bootstrap_enabled {
                            let _ = s.send_handshake(&temp_cid, b"NACK".to_vec());
                            return;
                        }
                        let _ = s.send_handshake(&temp_cid, b"NACK".to_vec());
                        let init_key = Encryption::gen_x25519(true).unwrap();
                        let mut tss_salt = vec![0u8; 64];
                        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut tss_salt);
                        let mut sign_data = init_key.1.clone();
                        sign_data.extend_from_slice(&tss_salt);
                        let signed_init = Encryption::ed25519_sign(&prv_key, &sign_data).unwrap();
                        let _ = s.send_handshake(&temp_cid, signed_init);
                        let signed_client_ephemeral = match s.recv_handshake(&temp_cid, Some(Duration::from_secs(5))).await {
                            Ok(Some(p)) => p,
                            _ => return,
                        };
                        let client_ephemeral_pub = match Encryption::ed25519_verify(&client_pub, &signed_client_ephemeral) {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        let tss = Encryption::shared_secret(&init_key.0, &client_ephemeral_pub).unwrap();
                        
                        let bootstrap_totp_bytes = fs::read(&bootstrap_totp).ok().and_then(|d| Encryption::decryptGCM(&d, &ark, None).ok()).unwrap_or_default();
                        let base32_sec = base64::encode(&bootstrap_totp_bytes);
                        let _hash = Encryption::basic_kdf(&client_pub, b"", 6);
                        let fid = hex::encode(&rand::random::<[u8; 8]>());
                        let auth_path = format!("./auth keys/{}", fid);
                        let signed_client = Encryption::ed25519_sign(&prv_key, &client_pub).unwrap();
                        let _ = fs::write(&auth_path, signed_client);
                        keys_map.lock().unwrap().insert(_hash.clone(), tss);
                        counters_map.lock().unwrap().insert(_hash.clone(), [1, 0]);
                        admin_map.lock().unwrap().insert(_hash.clone(), false);
                        usernames_map.lock().unwrap().insert(_hash.clone(), fid);
                        let _ = s.auth_finished(&temp_cid, _hash, None);
                    }
                }
            })
        });
        let callbacks = backend::ServerCallbacks {
            handshake_worker: Some(handshake_worker),
            on_exchange: None,
            on_disconnect: None,
        };
        let server = backend::Server::new(host, port, callbacks, 1, simult_exchanges)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        let server_arc = Arc::new(server);
        *server_ref_for_hs.lock().unwrap() = Some(Arc::clone(&server_arc));
        Ok(Self {
            rt,
            server: server_arc,
            at_rest_key,
            signing_keys,
            enable_bootstrap,
            keys,
            counters,
            admin,
            usernames,
            pending_bootstrap_totp,
            admin_totp_path,
            bootstrap_totp_path,
        })
    }
    fn start(&self) {
        let server = Arc::clone(&self.server);
        self.rt.spawn(async move {
            let _ = server.start().await;
        });
    }
    fn close(&self) {
        let server = Arc::clone(&self.server);
        self.rt.block_on(async move {
            server.stop().await;
        });
    }
    #[pyo3(signature = (payload, eid=None, client_id=None))]
    fn send(&self, py: Python, payload: &PyBytes, eid: Option<&PyBytes>, client_id: Option<&PyBytes>) -> PyResult<PyObject> {
        let cid_bytes = client_id.ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("client_id is required"))?.as_bytes();
        let e_bytes = match eid {
            Some(e) => {
                if e.as_bytes().len() != EID_SIZE {
                    return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("eid must be exactly 8 bytes"));
                }
                let mut arr = [0u8; EID_SIZE];
                arr.copy_from_slice(e.as_bytes());
                Some(arr)
            }
            None => None,
        };
        let keys = self.keys.lock().unwrap();
        let ekey = keys.get(cid_bytes).ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Client is not authenticated".into())))?;
        
        let mut counters = self.counters.lock().unwrap();
        let [sc, rc] = counters.get_mut(cid_bytes).ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Client is not authenticated".into())))?;
        let ctr_bytes = sc.to_be_bytes();
        *sc += 1;
        drop(counters);
        drop(keys);
        let final_eid = match e_bytes {
            Some(e) => e,
            None => new_eid().map_err(|e| PyErr::new::<ProtocolError, _>(e))?,
        };
        let mut enc_data = ctr_bytes.to_vec();
        let mut aad = final_eid.to_vec();
        aad.extend_from_slice(&ctr_bytes);
        aad.extend_from_slice(b"1");
        let encrypted = Encryption::encryptGCM(payload.as_bytes(), ekey, Some(&aad))
            .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
        enc_data.extend_from_slice(&encrypted);
        let sent_eid = self.server.send(enc_data, cid_bytes, Some(final_eid))
            .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?;
        Ok(PyBytes::new(py, &sent_eid).into())
    }
    #[pyo3(signature = (client_id, eid, timeout=MAX_TIMEOUT))]
    fn recv(&self, py: Python, client_id: &PyBytes, eid: &PyBytes, timeout: u64) -> PyResult<Option<PyObject>> {
        let cid_bytes = client_id.as_bytes();
        let e_bytes = eid.as_bytes();
        if e_bytes.len() != EID_SIZE {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("eid must be exactly 8 bytes"));
        }
        let mut target_eid = [0u8; EID_SIZE];
        target_eid.copy_from_slice(e_bytes);
        let keys = self.keys.lock().unwrap();
        let ekey = keys.get(cid_bytes).ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Client is not authenticated".into())))?.clone();
        drop(keys);
        let timeout_dur = std::time::Duration::from_secs(timeout.min(MAX_TIMEOUT));
        let raw_opt = self.rt.block_on(async {
            self.server.recv(cid_bytes, target_eid, Some(timeout_dur)).await
        }).map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?;
        let raw = match raw_opt {
            Some(r) => r,
            None => return Ok(None),
        };
        if raw.len() < 8 {
            return Err(PyErr::new::<ProtocolError, _>(ProtocolError::new("Invalid response".into())));
        }
        let ctr_bytes = &raw[..8];
        let counter = u64::from_be_bytes(ctr_bytes.try_into().unwrap());
        let mut aad = target_eid.to_vec();
        aad.extend_from_slice(ctr_bytes);
        aad.extend_from_slice(b"0");
        let decrypted = Encryption::decryptGCM(&raw[8..], &ekey, Some(&aad))
            .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
        let mut counters = self.counters.lock().unwrap();
        let [sc, rc] = counters.get_mut(cid_bytes).ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Client is not authenticated".into())))?;
        if counter <= *rc {
            return Err(PyErr::new::<ProtocolError, _>(ProtocolError::new("Counter Error".into())));
        }
        *rc = counter;
        Ok(Some(PyBytes::new(py, &decrypted).into()))
    }
}
#[pyclass]
pub struct TCPClient {
    rt: Runtime,
    client: Option<backend::Client>,
    ekey: Option<Vec<u8>>,
    sc: u64,
    rc: u64,
    server_cert: Vec<u8>,
}
#[pymethods]
impl TCPClient {
    #[new]
    #[pyo3(signature = (host, port, password, admin_auth_code=None, on_exchange=None, simult_exchanges=4))]
    fn new(
        host: String,
        port: u16,
        password: String,
        admin_auth_code: Option<String>,
        on_exchange: Option<PyObject>,
        simult_exchanges: usize,
    ) -> PyResult<Self> {
        let rt = Runtime::new()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
        let is_admin = admin_auth_code.is_some();
        let client_keys_dir = "./client keys";
        fs::create_dir_all(client_keys_dir)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
        let salt_path = format!("{}/salt", client_keys_dir);
        let auth_key_path = format!("{}/auth_key", client_keys_dir);
        let server_cert_path = format!("{}/server_cert", client_keys_dir);
        let mut salt = vec![0u8; SALT_SIZE];
        if Path::new(&salt_path).exists() {
            if let Ok(s) = fs::read(&salt_path) {
                if s.len() == SALT_SIZE {
                    salt = s;
                } else {
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
                    let _ = fs::remove_file(&salt_path);
                    let _ = fs::remove_file(&auth_key_path);
                }
            }
        } else {
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
            let _ = fs::write(&salt_path, &salt);
        }
        let at_rest_key = derive_at_rest_key(&password, &salt_path).unwrap_or_default();
        let mut sig_prv = vec![];
        let mut pub_key = vec![];
        let mut server_cert = vec![];
        if !is_admin {
            if let Ok(encrypted_prv) = fs::read(&auth_key_path) {
                if let Ok(decrypted) = Encryption::decryptGCM(&encrypted_prv, &at_rest_key, None) {
                    sig_prv = decrypted;
                    if let Ok(pub_k) = Encryption::get_pub(&sig_prv, false) {
                        pub_key = pub_k;
                    }
                }
            }
            if Path::new(&server_cert_path).exists() {
                if let Ok(sc_bytes) = fs::read(&server_cert_path) {
                    if !pub_key.is_empty() {
                        if let Ok(verified_cert) = Encryption::ed25519_verify(&pub_key, &sc_bytes) {
                            server_cert = verified_cert;
                        }
                    }
                }
            }
        }
        let callbacks = backend::ClientCallbacks { on_exchange: None };
        let backend_client = rt
            .block_on(async {
                backend::Client::connect(host, port, callbacks, simult_exchanges).await
            })
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyConnectionError, _>(e.to_string()))?;
        let mut client_inst = Self {
            rt,
            client: Some(backend_client),
            ekey: None,
            sc: 1,
            rc: 0,
            server_cert,
        };
        client_inst.authenticate(is_admin, admin_auth_code, sig_prv, pub_key, salt, at_rest_key)?;
        Ok(client_inst)
    }
    #[pyo3(signature = (payload, eid=None))]
    fn send(&mut self, py: Python, payload: &PyBytes, eid: Option<&PyBytes>) -> PyResult<PyObject> {
        let ekey = self
            .ekey
            .as_ref()
            .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Client is not authenticated".into())))?;
        let e_bytes = match eid {
            Some(e) => {
                if e.as_bytes().len() != EID_SIZE {
                    return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("eid must be exactly 8 bytes"));
                }
                let mut arr = [0u8; EID_SIZE];
                arr.copy_from_slice(e.as_bytes());
                arr
            }
            None => new_eid().map_err(|e| PyErr::new::<ProtocolError, _>(e))?,
        };
        let ctr_bytes = self.sc.to_be_bytes();
        self.sc += 1;
        let mut aad = e_bytes.to_vec();
        aad.extend_from_slice(&ctr_bytes);
        aad.extend_from_slice(b"0");
        let encrypted = Encryption::encryptGCM(payload.as_bytes(), ekey, Some(&aad))
            .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
        let mut wire_data = ctr_bytes.to_vec();
        wire_data.extend_from_slice(&encrypted);
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Connection closed".into())))?;
        let sent_eid = client
            .send(wire_data, Some(e_bytes))
            .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?;
        Ok(PyBytes::new(py, &sent_eid).into())
    }
    #[pyo3(signature = (eid, timeout=MAX_TIMEOUT))]
    fn recv(&mut self, py: Python, eid: &PyBytes, timeout: u64) -> PyResult<Option<PyObject>> {
        let ekey = self
            .ekey
            .as_ref()
            .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Client is not authenticated".into())))?
            .clone();
        let e_bytes = eid.as_bytes();
        if e_bytes.len() != EID_SIZE {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("eid must be exactly 8 bytes"));
        }
        let mut target_eid = [0u8; EID_SIZE];
        target_eid.copy_from_slice(e_bytes);
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Connection closed".into())))?;
        let timeout_dur = Duration::from_secs(timeout.min(MAX_TIMEOUT));
        let raw_opt = self
            .rt
            .block_on(async { client.recv(target_eid, Some(timeout_dur)).await })
            .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?;
        let raw = match raw_opt {
            Some(r) => r,
            None => return Ok(None),
        };
        if raw.len() < 8 {
            return Err(PyErr::new::<ProtocolError, _>(ProtocolError::new("Invalid encrypted response".into())));
        }
        let ctr_bytes = &raw[..8];
        let counter = u64::from_be_bytes(ctr_bytes.try_into().unwrap());
        if counter <= self.rc {
            return Err(PyErr::new::<ProtocolError, _>(ProtocolError::new("Counter Error".into())));
        }
        self.rc = counter;
        let mut aad = target_eid.to_vec();
        aad.extend_from_slice(ctr_bytes);
        aad.extend_from_slice(b"1");
        let decrypted = Encryption::decryptGCM(&raw[8..], &ekey, Some(&aad))
            .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
        Ok(Some(PyBytes::new(py, &decrypted).into()))
    }
    fn set_backpressure(&self, enabled: bool) -> PyResult<()> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Connection closed".into())))?;
        client
            .set_backpressure(enabled)
            .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))
    }
    fn close(&mut self) {
        if let Some(client) = self.client.take() {
            client.close();
        }
        self.ekey = None;
    }
}
impl TCPClient {
    fn authenticate(
        &mut self,
        is_admin: bool,
        admin_auth_code: Option<String>,
        mut sig_prv: Vec<u8>,
        mut pub_key: Vec<u8>,
        salt: Vec<u8>,
        at_rest_key: Vec<u8>,
    ) -> PyResult<()> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Connection closed".into())))?;
        if is_admin {
            let admin_code = admin_auth_code
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("admin_auth_code must not be empty"))?;
            let init_key = Encryption::gen_x25519(true)
                .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
            let mut req_admin = b"REQ_ADMIN".to_vec();
            req_admin.extend_from_slice(&init_key.1);
            client
                .send_handshake(req_admin)
                .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?;
            let server_cert = self
                .rt
                .block_on(async { client.recv_handshake(Some(Duration::from_secs(1))).await })
                .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?
                .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Handshake timed out".into())))?;
            if !self.server_cert.is_empty() && self.server_cert != server_cert {
                return Err(PyErr::new::<ProtocolError, _>(ProtocolError::new("Server certificate is invalid".into())));
            }
            self.server_cert = server_cert.clone();
            let signed_resp = self
                .rt
                .block_on(async { client.recv_handshake(Some(Duration::from_secs(1))).await })
                .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?
                .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Handshake timed out".into())))?;
            let response = Encryption::ed25519_verify(&server_cert, &signed_resp)
                .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
            if response.len() < 64 {
                return Err(PyErr::new::<ProtocolError, _>(ProtocolError::new("Invalid response length".into())));
            }
            let server_ephemeral_pub = &response[..response.len() - 64];
            let tss_salt = &response[response.len() - 64..];
            let shared_sec = Encryption::shared_secret(&init_key.0, server_ephemeral_pub)
                .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
            let mut kdf_input = tss_salt.to_vec();
            kdf_input.extend_from_slice(&shared_sec);
            let tss = Encryption::kdf(admin_code.as_bytes(), &kdf_input, 5)
                .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
            let mut sc = 1u64;
            let mut rc = 0u64;
            let send_enc = |payload: &[u8], sc_val: &mut u64| -> Result<(), ProtocolError> {
                let ctr = sc_val.to_be_bytes();
                *sc_val += 1;
                let mut aad = ctr.to_vec();
                aad.extend_from_slice(b"0");
                let enc = Encryption::encryptGCM(payload, &tss, Some(&aad))
                    .map_err(|e| ProtocolError::new(e.to_string()))?;
                let mut wire = ctr.to_vec();
                wire.extend_from_slice(&enc);
                client.send_handshake(wire).map_err(|e| ProtocolError::from(e))
            };
            let recv_enc = |timeout_secs: u64, rc_val: &mut u64| -> Result<Vec<u8>, ProtocolError> {
                let wire = self
                    .rt
                    .block_on(async { client.recv_handshake(Some(Duration::from_secs(timeout_secs))).await })
                    .map_err(|e| ProtocolError::from(e))?
                    .ok_or_else(|| ProtocolError::new("Timed out".into()))?;
                if wire.len() < 8 {
                    return Err(ProtocolError::new("Timed out".into()));
                }
                let ctr = &wire[..8];
                let counter = u64::from_be_bytes(ctr.try_into().unwrap());
                if counter != *rc_val + 1 {
                    return Err(ProtocolError::new("Counter Error".into()));
                }
                *rc_val = counter;
                let mut aad = ctr.to_vec();
                aad.extend_from_slice(b"1");
                Encryption::decryptGCM(&wire[8..], &tss, Some(&aad))
                    .map_err(|e| ProtocolError::new(e.to_string()))
            };
            let mut nonce2 = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce2);
            send_enc(&nonce2, &mut sc)?;
            let nonce1 = recv_enc(5, &mut rc)?;
            let mut nhash_input = nonce1;
            nhash_input.extend_from_slice(&nonce2);
            let nhash = Encryption::basic_kdf(&nhash_input, b"", 64);
            send_enc(&nhash, &mut sc)?;
            let final_check = recv_enc(1, &mut rc)?;
            let expected_final = Encryption::basic_kdf(&nhash, b"", 64);
            if final_check != expected_final {
                return Err(PyErr::new::<ProtocolError, _>(ProtocolError::new("Auth Failed".into())));
            }
            self.ekey = Some(tss);
            self.sc = sc;
            self.rc = rc;
        } else {
            let is_bootstrap = pub_key.is_empty() || !Path::new("./client keys/auth_key").exists();
            if is_bootstrap {
                let sig_keys = Encryption::gen_ed25519(true)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                sig_prv = sig_keys.0;
                pub_key = sig_keys.1;
            }
            client
                .send_handshake(pub_key.clone())
                .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?;
            let server_cert = self
                .rt
                .block_on(async { client.recv_handshake(Some(Duration::from_secs(1))).await })
                .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?
                .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Handshake timed out".into())))?;
            if !self.server_cert.is_empty() && self.server_cert != server_cert {
                return Err(PyErr::new::<ProtocolError, _>(ProtocolError::new("Server certificate is invalid".into())));
            }
            self.server_cert = server_cert.clone();
            let signed_cert = Encryption::ed25519_sign(&sig_prv, &server_cert)
                .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
            let _ = fs::write("./client keys/server_cert", signed_cert);
            let status = self
                .rt
                .block_on(async { client.recv_handshake(Some(Duration::from_secs(5))).await })
                .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?
                .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Auth Denied".into())))?;
            if status == b"ACK" {
                let signed_resp = self
                    .rt
                    .block_on(async { client.recv_handshake(Some(Duration::from_secs(5))).await })
                    .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?
                    .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Handshake timed out".into())))?;
                let server_ephemeral_pub = Encryption::ed25519_verify(&server_cert, &signed_resp)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                let keys = Encryption::gen_x25519(true)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                let signed_ephem = Encryption::ed25519_sign(&sig_prv, &keys.1)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                client
                    .send_handshake(signed_ephem)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?;
                let shared_sec = Encryption::shared_secret(&keys.0, &server_ephemeral_pub)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                self.ekey = Some(shared_sec);
                self.sc = 1;
                self.rc = 0;
            } else if status == b"NACK" {
                let totp_code = rpassword::prompt_password("Auth Key Security Code: ")
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                let signed_resp = self
                    .rt
                    .block_on(async { client.recv_handshake(Some(Duration::from_secs(5))).await })
                    .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?
                    .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Handshake timed out".into())))?;
                let response = Encryption::ed25519_verify(&server_cert, &signed_resp)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                if response.len() < 64 {
                    return Err(PyErr::new::<ProtocolError, _>(ProtocolError::new("Invalid response".into())));
                }
                let server_ephemeral_pub = &response[..response.len() - 64];
                let tss_salt = &response[response.len() - 64..];
                let keys = Encryption::gen_x25519(true)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                let signed_ephem = Encryption::ed25519_sign(&sig_prv, &keys.1)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                client
                    .send_handshake(signed_ephem)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?;
                let tss_shared = Encryption::shared_secret(&keys.0, server_ephemeral_pub)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                let mut kdf_input = tss_salt.to_vec();
                kdf_input.extend_from_slice(&tss_shared);
                let tss = Encryption::kdf(totp_code.as_bytes(), &kdf_input, 5)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                let mut sc = 1u64;
                let mut rc = 0u64;
                let send_enc = |payload: &[u8], sc_val: &mut u64| -> Result<(), ProtocolError> {
                    let ctr = sc_val.to_be_bytes();
                    *sc_val += 1;
                    let mut aad = ctr.to_vec();
                    aad.extend_from_slice(b"0");
                    let enc = Encryption::encryptGCM(payload, &tss, Some(&aad))
                        .map_err(|e| ProtocolError::new(e.to_string()))?;
                    let mut wire = ctr.to_vec();
                    wire.extend_from_slice(&enc);
                    client.send_handshake(wire).map_err(|e| ProtocolError::from(e))
                };
                let recv_enc = |timeout_secs: u64, rc_val: &mut u64| -> Result<Vec<u8>, ProtocolError> {
                    let wire = self
                        .rt
                        .block_on(async { client.recv_handshake(Some(Duration::from_secs(timeout_secs))).await })
                        .map_err(|e| ProtocolError::from(e))?
                        .ok_or_else(|| ProtocolError::new("Timed out".into()))?;
                    if wire.len() < 8 {
                        return Err(ProtocolError::new("Timed out".into()));
                    }
                    let ctr = &wire[..8];
                    let counter = u64::from_be_bytes(ctr.try_into().unwrap());
                    if counter != *rc_val + 1 {
                        return Err(ProtocolError::new("Counter Error".into()));
                    }
                    *rc_val = counter;
                    let mut aad = ctr.to_vec();
                    aad.extend_from_slice(b"1");
                    Encryption::decryptGCM(&wire[8..], &tss, Some(&aad))
                        .map_err(|e| ProtocolError::new(e.to_string()))
                };
                let mut nonce2 = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce2);
                send_enc(&nonce2, &mut sc)?;
                let nonce1 = recv_enc(5, &mut rc)?;
                let mut nhash_input = nonce1;
                nhash_input.extend_from_slice(&nonce2);
                let nhash = Encryption::basic_kdf(&nhash_input, b"", 64);
                send_enc(&nhash, &mut sc)?;
                let final_check = recv_enc(1, &mut rc)?;
                let expected_final = Encryption::basic_kdf(&nhash, b"", 64);
                if final_check != expected_final {
                    return Err(PyErr::new::<ProtocolError, _>(ProtocolError::new("Auth Failed".into())));
                }
                let server_cert2 = self
                    .rt
                    .block_on(async { client.recv_handshake(Some(Duration::from_secs(5))).await })
                    .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?
                    .ok_or_else(|| PyErr::new::<ProtocolError, _>(ProtocolError::new("Handshake timed out".into())))?;
                let response2 = Encryption::ed25519_verify(&server_cert, &server_cert2)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                let keys2 = Encryption::gen_x25519(true)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                let signed_ephem2 = Encryption::ed25519_sign(&sig_prv, &keys2.1)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                client
                    .send_handshake(signed_ephem2)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?;
                let shared_sec2 = Encryption::shared_secret(&keys2.0, &response2)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                self.ekey = Some(shared_sec2);
                self.sc = sc;
                self.rc = rc;
                let encrypted_prv = Encryption::encryptGCM(&sig_prv, &at_rest_key, None)
                    .map_err(|e| PyErr::new::<ProtocolError, _>(ProtocolError::new(e.to_string())))?;
                let _ = fs::write("./client keys/auth_key", encrypted_prv);
                let _ = fs::write("./client keys/salt", &salt);
            } else {
                return Err(PyErr::new::<ProtocolError, _>(ProtocolError::new("Auth Denied".into())));
            }
        }
        client.auth_finished().map_err(|e| PyErr::new::<ProtocolError, _>(e.into()))?;
        Ok(())
    }
}
#[pymodule]
fn network2(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<TCPServer>()?;
    m.add_class::<TCPClient>()?;
    m.add_class::<ProtocolError>()?;
    m.add("SALT_SIZE", SALT_SIZE)?;
    m.add("MAX_TIMEOUT", MAX_TIMEOUT)?;
    m.add("EID_SIZE", EID_SIZE)?;
    Ok(())
}