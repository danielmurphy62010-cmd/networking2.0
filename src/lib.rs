//! Python-compatible entry point for the `network2` extension.
//!
//! Build with maturin. The public classes mirror network.py's TCPServer and
//! TCPClient and retain Python bytes at the boundary rather than exposing
//! Rust's internal Vec<u8> representation.

mod crypto;
mod protocol;
mod transport;

use pyo3::{
    create_exception,
    exceptions::{PyException, PyValueError},
    prelude::*,
    types::{PyBytes, PyModule},
};
use std::time::Duration;

create_exception!(network2, ProtocolError, PyException);

fn protocol_error(error: protocol::ProtocolFailure) -> PyErr {
    PyErr::new::<ProtocolError, _>(error.to_string())
}

fn timeout_from_seconds(value: Option<f64>, default_seconds: Option<f64>) -> PyResult<Option<Duration>> {
    let seconds = value.or(default_seconds);
    match seconds {
        None => Ok(None),
        Some(value) if !value.is_finite() || value < 0.0 || value > 365.0 * 24.0 * 60.0 * 60.0 => {
            Err(PyValueError::new_err("timeout must be between 0 and 365 days"))
        }
        Some(value) => Ok(Some(Duration::from_secs_f64(value))),
    }
}

fn target_as_bytes(value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(bytes) = value.cast::<PyBytes>() {
        return Ok(bytes.as_bytes().to_vec());
    }
    if let Ok(text) = value.extract::<String>() {
        return Ok(text.into_bytes());
    }
    Err(PyValueError::new_err("target must be bytes or a string"))
}

#[pyclass(name = "TCPServer", module = "network2", weakref)]
struct PyTCPServer {
    inner: std::sync::Arc<protocol::ProtocolServer>,
}

#[pymethods]
impl PyTCPServer {
    #[new]
    #[pyo3(signature = (host, port, password, newTOTP=false, on_exchange=None, simult_exchanges=4))]
    #[allow(non_snake_case)]
    fn new(
        py: Python<'_>,
        host: String,
        port: u16,
        password: String,
        newTOTP: bool,
        on_exchange: Option<Py<PyAny>>,
        simult_exchanges: usize,
    ) -> PyResult<Py<Self>> {
        let inner = py
            .detach(move || {
                protocol::ProtocolServer::new(
                    host,
                    port,
                    password,
                    newTOTP,
                    on_exchange,
                    simult_exchanges,
                )
            })
            .map_err(protocol_error)?;
        let wrapper = Py::new(py, Self { inner: inner.clone() })?;
        inner.set_python_self(wrapper.clone_ref(py).into_any());
        Ok(wrapper)
    }

    /// The constructor starts the listener, matching the legacy implementation.
    /// Calling start again is harmless in this replacement.
    fn start(&self) -> PyResult<()> {
        Ok(())
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let inner = self.inner.clone();
        py.detach(move || inner.close());
        Ok(())
    }

    #[pyo3(signature = (payload, eid=None, client_id=None))]
    fn send(
        &self,
        payload: &[u8],
        eid: Option<&[u8]>,
        client_id: Option<&[u8]>,
    ) -> PyResult<Py<PyBytes>> {
        let client_id = client_id.ok_or_else(|| PyValueError::new_err("client_id is required"))?;
        if eid.is_some_and(|value| value.len() != 8) {
            return Err(PyValueError::new_err("eid must be exactly 8 bytes"));
        }
        let result = self
            .inner
            .send(payload, eid, client_id)
            .map_err(protocol_error)?;
        Python::attach(|py| Ok(PyBytes::new(py, &result).unbind()))
    }

    #[pyo3(signature = (client_id, eid, timeout=10.0))]
    fn recv(
        &self,
        py: Python<'_>,
        client_id: &[u8],
        eid: &[u8],
        timeout: Option<f64>,
    ) -> PyResult<Option<Py<PyBytes>>> {
        if eid.len() != 8 {
            return Err(PyValueError::new_err("eid must be exactly 8 bytes"));
        }
        let timeout = timeout_from_seconds(timeout, Some(10.0))?;
        let inner = self.inner.clone();
        let cid = client_id.to_vec();
        let exchange = eid.to_vec();
        let result = py
            .detach(move || inner.recv(&cid, &exchange, timeout))
            .map_err(protocol_error)?;
        Ok(result.map(|value| PyBytes::new(py, &value).unbind()))
    }

    #[pyo3(signature = (client_id, close=true))]
    fn close_client(&self, client_id: &[u8], close: bool) -> PyResult<()> {
        self.inner
            .close_client(client_id, close)
            .map_err(protocol_error)
    }

    #[pyo3(signature = (client_id, enabled=true))]
    fn set_backpressure(&self, client_id: &[u8], enabled: bool) -> PyResult<()> {
        self.inner
            .set_backpressure(client_id, enabled)
            .map_err(protocol_error)
    }

    fn is_authed(&self, client_id: &[u8]) -> bool {
        self.inner.is_authed(client_id)
    }

    #[getter(signing_keys)]
    fn signing_keys(&self, py: Python<'_>) -> (Py<PyBytes>, Py<PyBytes>) {
        let (private, public) = self.inner.signing_keys();
        (
            PyBytes::new(py, &private).unbind(),
            PyBytes::new(py, &public).unbind(),
        )
    }

    #[getter(MAGIC1)]
    fn magic1(&self, py: Python<'_>) -> Py<PyBytes> {
        // Server-level framing markers are shared by all accepted connections.
        // The transport currently exposes them through its live transport.
        let bytes = self.inner.magic1().unwrap_or_default();
        PyBytes::new(py, &bytes).unbind()
    }

    #[getter(MAGIC2)]
    fn magic2(&self, py: Python<'_>) -> Py<PyBytes> {
        let bytes = self.inner.magic2().unwrap_or_default();
        PyBytes::new(py, &bytes).unbind()
    }

    #[getter(_enable_bootstrap)]
    fn enable_bootstrap_get(&self) -> bool {
        self.inner.is_bootstrap_enabled()
    }

    #[setter(_enable_bootstrap)]
    fn enable_bootstrap_set(&self, value: bool) {
        // Direct attribute assignment is retained for compatibility. The admin
        // RPC methods remain the preferred way to change this state.
        self.inner.set_bootstrap_enabled_internal(value);
    }

    #[getter(last_bootstrap)]
    fn last_bootstrap(&self) -> Option<f64> {
        self.inner.last_bootstrap_seconds()
    }

    #[getter(last_admin)]
    fn last_admin(&self) -> Option<f64> {
        self.inner.last_admin_seconds()
    }

    fn setup_bootstrap_totp(&self, client_id: &[u8], eid: &[u8]) -> PyResult<()> {
        self.inner
            .setup_bootstrap_totp(client_id, eid)
            .map_err(protocol_error)
    }

    fn verify_bootstrap_totp(&self, client_id: &[u8], eid: &[u8], code: &str) -> PyResult<()> {
        self.inner
            .verify_bootstrap_totp(client_id, eid, code)
            .map_err(protocol_error)
    }

    fn bootstrap_status(&self, client_id: &[u8], eid: &[u8]) -> PyResult<()> {
        self.inner
            .bootstrap_status(client_id, eid)
            .map_err(protocol_error)
    }

    fn bootstrapping_enabled(&self, client_id: &[u8], eid: &[u8]) -> PyResult<()> {
        self.inner
            .bootstrapping_enabled(client_id, eid)
            .map_err(protocol_error)
    }

    fn enable_bootstrap(&self, client_id: &[u8], eid: &[u8]) -> PyResult<()> {
        self.inner
            .enable_bootstrap(client_id, eid, true)
            .map_err(protocol_error)
    }

    fn disable_bootstrap(&self, client_id: &[u8], eid: &[u8]) -> PyResult<()> {
        self.inner
            .enable_bootstrap(client_id, eid, false)
            .map_err(protocol_error)
    }

    fn list_users(&self, client_id: &[u8], eid: &[u8]) -> PyResult<()> {
        self.inner.list_users(client_id, eid).map_err(protocol_error)
    }

    fn list_connections(&self, client_id: &[u8], eid: &[u8]) -> PyResult<()> {
        self.inner
            .list_connections(client_id, eid)
            .map_err(protocol_error)
    }

    fn server_cert(&self, client_id: &[u8], eid: &[u8]) -> PyResult<()> {
        self.inner.server_cert(client_id, eid).map_err(protocol_error)
    }

    fn rename_username(
        &self,
        client_id: &[u8],
        eid: &[u8],
        target_cid: &Bound<'_, PyAny>,
        new_username: &str,
    ) -> PyResult<()> {
        let target = target_as_bytes(target_cid)?;
        self.inner
            .rename_username(client_id, eid, &target, new_username)
            .map_err(protocol_error)
    }

    fn deauth_client(
        &self,
        client_id: &[u8],
        eid: &[u8],
        target_cid: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let target = target_as_bytes(target_cid)?;
        self.inner
            .deauth_client(client_id, eid, &target)
            .map_err(protocol_error)
    }

    fn disconnect_client(
        &self,
        client_id: &[u8],
        eid: &[u8],
        target_cid: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let target = target_as_bytes(target_cid)?;
        self.inner
            .disconnect_client(client_id, eid, &target)
            .map_err(protocol_error)
    }
}

#[pyclass(name = "TCPClient", module = "network2", weakref)]
struct PyTCPClient {
    inner: std::sync::Arc<protocol::ProtocolClient>,
}

#[pymethods]
impl PyTCPClient {
    #[new]
    #[pyo3(signature = (host, port, password, admin_auth_code=None, on_exchange=None, simult_exchanges=4))]
    fn new(
        py: Python<'_>,
        host: String,
        port: u16,
        password: String,
        admin_auth_code: Option<String>,
        on_exchange: Option<Py<PyAny>>,
        simult_exchanges: usize,
    ) -> PyResult<Py<Self>> {
        let inner = py
            .detach(move || {
                protocol::ProtocolClient::connect(
                    host,
                    port,
                    password,
                    admin_auth_code,
                    on_exchange,
                    simult_exchanges,
                )
            })
            .map_err(protocol_error)?;
        let wrapper = Py::new(py, Self { inner: inner.clone() })?;
        inner.set_python_self(wrapper.clone_ref(py).into_any());
        Ok(wrapper)
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let inner = self.inner.clone();
        py.detach(move || inner.close());
        Ok(())
    }

    #[pyo3(signature = (payload, eid=None))]
    fn send(&self, py: Python<'_>, payload: &[u8], eid: Option<&[u8]>) -> PyResult<Py<PyBytes>> {
        if eid.is_some_and(|value| value.len() != 8) {
            return Err(PyValueError::new_err("eid must be exactly 8 bytes"));
        }
        let inner = self.inner.clone();
        let payload = payload.to_vec();
        let eid = eid.map(|value| value.to_vec());
        let result = py
            .detach(move || inner.send(&payload, eid.as_deref()))
            .map_err(protocol_error)?;
        Ok(PyBytes::new(py, &result).unbind())
    }

    #[pyo3(signature = (eid, timeout=10.0))]
    fn recv(
        &self,
        py: Python<'_>,
        eid: &[u8],
        timeout: Option<f64>,
    ) -> PyResult<Option<Py<PyBytes>>> {
        if eid.len() != 8 {
            return Err(PyValueError::new_err("eid must be exactly 8 bytes"));
        }
        // Omitted timeout defaults to 10 seconds; explicit None means wait forever.
        let timeout = timeout_from_seconds(timeout, None)?;
        let inner = self.inner.clone();
        let exchange = eid.to_vec();
        let result = py
            .detach(move || inner.recv(&exchange, timeout))
            .map_err(protocol_error)?;
        Ok(result.map(|value| PyBytes::new(py, &value).unbind()))
    }

    #[pyo3(signature = (enabled=true))]
    fn set_backpressure(&self, enabled: bool) -> PyResult<()> {
        self.inner
            .set_backpressure(enabled)
            .map_err(protocol_error)
    }

    fn is_authed(&self) -> bool {
        self.inner.is_authed()
    }

    #[getter(cid)]
    fn cid(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &[]).unbind()
    }

    #[getter(MAGIC1)]
    fn magic1(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let value = self.inner.magic1().map_err(protocol_error)?;
        Ok(PyBytes::new(py, &value).unbind())
    }

    #[getter(MAGIC2)]
    fn magic2(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let value = self.inner.magic2().map_err(protocol_error)?;
        Ok(PyBytes::new(py, &value).unbind())
    }
}

#[pymodule]
fn network2(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("ProtocolError", module.py().get_type::<ProtocolError>())?;
    module.add_class::<PyTCPServer>()?;
    module.add_class::<PyTCPClient>()?;
    module.add("SALT_SIZE", crypto::SALT_SIZE)?;
    module.add("MAX_TIMEOUT", 10)?;
    module.add("EID_SIZE", 8)?;
    module.add("MAX_UNAUTH_PAYLOAD", transport::MAX_UNAUTH_PAYLOAD)?;
    module.add("MAX_AUTH_PAYLOAD", transport::MAX_AUTH_PAYLOAD)?;
    module.add("QUEUE_LIMIT", transport::QUEUE_LIMIT)?;
    Ok(())
}
