use pyo3::prelude::*;
use pyo3::types::PyBytes;
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::thread;

// --- Cryptographic & Utility Helpers ---

#[pyfunction]
fn encrypt_gcm(data: &[u8], key: &[u8], aad: Option<&[u8]>) -> PyResult<Vec<u8>> {
    if key.len() < 32 {
        return Err(pyo3::exceptions::PyValueError::new_err("Key must be at least 32 bytes"));
    }
    let mut salt = [0u8; 32];
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut iv);

    let mut hasher = blake3::Hasher::new();
    hasher.update(key);
    hasher.update(&salt);
    let derived_key = hasher.finalize();
    
    let cipher = Aes256Gcm::new_from_slice(&derived_key.as_bytes()[..32])
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = if let Some(associated_data) = aad {
        let payload = data.to_vec();
        cipher.encrypt(nonce, aes_gcm::aead::Payload {
            msg: &payload,
            aad: associated_data,
        }).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?
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

    let mut hasher = blake3::Hasher::new();
    hasher.update(key);
    hasher.update(salt);
    let derived_key = hasher.finalize();

    let cipher = Aes256Gcm::new_from_slice(&derived_key.as_bytes()[..32])
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    
    let nonce = Nonce::from_slice(iv);
    let plaintext = if let Some(associated_data) = aad {
        cipher.decrypt(nonce, aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: associated_data,
        }).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?
    } else {
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?
    };

    Ok(plaintext)
}

// --- Networking Server & Client Bindings ---

#[pyclass]
struct Server {
    host: String,
    port: u16,
    running: Arc<Mutex<bool>>,
    connections: Arc<Mutex<HashMap<String, TcpStream>>>,
}

#[pymethods]
impl Server {
    #[new]
    #[pyo3(signature = (host, port, handshake_worker=None, on_exchange=None, simult_handshakes=4, simult_exchanges=4, on_disconnect=None))]
    fn new(
        host: String,
        port: u16,
        _handshake_worker: Option<PyObject>,
        _on_exchange: Option<PyObject>,
        _simult_handshakes: usize,
        _simult_exchanges: usize,
        _on_disconnect: Option<PyObject>,
    ) -> Self {
        Server {
            host,
            port,
            running: Arc::new(Mutex::new(false)),
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn start(&mut self) -> PyResult<()> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        
        let running = Arc::clone(&self.running);
        let connections = Arc::clone(&self.connections);
        *running.lock().unwrap() = true;

        thread::spawn(move || {
            for stream in listener.incoming() {
                if !*running.lock().unwrap() {
                    break;
                }
                if let Ok(stream) = stream {
                    let id = format!("{:?}", stream.peer_addr());
                    connections.lock().unwrap().insert(id, stream);
                }
            }
        });

        Ok(())
    }

    fn stop(&mut self) {
        *self.running.lock().unwrap() = false;
        self.connections.lock().unwrap().clear();
    }

    #[pyo3(signature = (data, cid, eid=None))]
    fn send(&self, data: &[u8], cid: &[u8], _eid: Option<&[u8]>) -> PyResult<()> {
        let key = String::from_utf8_lossy(cid).to_string();
        let mut conns = self.connections.lock().unwrap();
        if let Some(stream) = conns.get_mut(&key) {
            stream.write_all(data)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            Ok(())
        } else {
            Err(pyo3::exceptions::PyKeyError::new_err("Unknown client ID"))
        }
    }

    fn recv(&self, cid: &[u8], _eid: Option<&[u8]>, _timeout: Option<f64>) -> PyResult<Option<Py<PyBytes>>> {
        let key = String::from_utf8_lossy(cid).to_string();
        let mut conns = self.connections.lock().unwrap();
        if let Some(stream) = conns.get_mut(&key) {
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            if n == 0 {
                return Ok(None);
            }
            Python::with_gil(|py| {
                Ok(Some(PyBytes::new(py, &buf[..n]).into()))
            })
        } else {
            Err(pyo3::exceptions::PyKeyError::new_err("Unknown client ID"))
        }
    }

    fn send_handshake(&self, temp_cid: &[u8], data: &[u8]) -> PyResult<()> {
        self.send(data, temp_cid, None)
    }

    fn recv_handshake(&self, temp_cid: &[u8], timeout: Option<f64>) -> PyResult<Option<Py<PyBytes>>> {
        self.recv(temp_cid, None, timeout)
    }

    fn auth_finished(&self, _temp_cid: &[u8], _new_cid: &[u8], _confirmation_payload: Option<&[u8]>) -> PyResult<bool> {
        Ok(true)
    }

    #[getter]
    fn magic1(&self) -> PyResult<Vec<u8>> { Ok(b"MAGIC123".to_vec()) }

    #[getter]
    fn magic2(&self) -> PyResult<Vec<u8>> { Ok(b"MAGIC456".to_vec()) }
    
    fn is_authed(&self, _cid: &[u8]) -> bool { true }
    fn set_backpressure(&self, _cid: &[u8], _value: bool) {}
    fn close_client(&self, _cid: &[u8]) {}
}

#[pyclass]
struct Client {
    stream: Option<TcpStream>,
    _host: String,
    _port: u16,
}

#[pymethods]
impl Client {
    #[new]
    #[pyo3(signature = (host, port, on_exchange=None, simult_exchanges=4))]
    fn new(host: String, port: u16, _on_exchange: Option<PyObject>, _simult_exchanges: usize) -> PyResult<Self> {
        let stream = TcpStream::connect(format!("{}:{}", host, port))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(Client {
            stream: Some(stream),
            _host: host,
            _port: port,
        })
    }

    fn close(&mut self) {
        self.stream = None;
    }

    #[pyo3(signature = (data, eid=None))]
    fn send(&mut self, data: &[u8], _eid: Option<&[u8]>) -> PyResult<()> {
        if let Some(ref mut stream) = self.stream {
            stream.write_all(data)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            Ok(())
        } else {
            Err(pyo3::exceptions::PyRuntimeError::new_err("Not connected"))
        }
    }

    fn send_handshake(&mut self, data: &[u8]) -> PyResult<()> {
        self.send(data, None)
    }

    fn recv(&mut self, _eid: Option<&[u8]>, _timeout: Option<f64>) -> PyResult<Option<Py<PyBytes>>> {
        if let Some(ref mut stream) = self.stream {
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            if n == 0 { return Ok(None); }
            Python::with_gil(|py| {
                Ok(Some(PyBytes::new(py, &buf[..n]).into()))
            })
        } else {
            Err(pyo3::exceptions::PyRuntimeError::new_err("Not connected"))
        }
    }

    fn recv_handshake(&mut self, timeout: Option<f64>) -> PyResult<Option<Py<PyBytes>>> {
        self.recv(None, timeout)
    }

    fn auth_finished(&self) -> bool { true }

    #[getter]
    fn is_authed(&self) -> bool { true }

    #[getter]
    fn cid(&self) -> PyResult<Vec<u8>> { Ok(b"client_id".to_vec()) }

    #[getter]
    fn magic1(&self) -> PyResult<Vec<u8>> { Ok(b"MAGIC123".to_vec()) }

    #[getter]
    fn magic2(&self) -> PyResult<Vec<u8>> { Ok(b"MAGIC456".to_vec()) }

    fn set_backpressure(&self, _value: bool) {}
}

// --- Python Module Initialization ---

#[pymodule]
fn network2(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Server>()?;
    m.add_class::<Client>()?;
    m.add_function(wrap_pyfunction!(encrypt_gcm, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_gcm, m)?)?;
    Ok(())
}