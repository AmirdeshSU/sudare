//! Python bindings: `import sudare; r = sudare.mask(text); r.masked; r.unmask(reply)`.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::path::PathBuf;
use sudare_core::{Engine, Policy, Prepared};

/// Masked text plus the token map, which stays inside this object.
#[pyclass(module = "sudare", name = "MaskResult", frozen)]
struct MaskResult {
    prepared: Prepared,
}

#[pymethods]
impl MaskResult {
    /// The masked text: safe to send to an LLM.
    #[getter]
    fn masked(&self) -> String {
        self.prepared.input.text().to_string()
    }

    #[getter]
    fn parser(&self) -> String {
        self.prepared.parser.clone()
    }

    /// (token, entity type, scope) for every masked value. No real values.
    fn tokens(&self) -> Vec<(String, String, String)> {
        self.prepared
            .map
            .tokens()
            .map(|(t, k, s)| (t.to_string(), k.label(), format!("{s:?}").to_lowercase()))
            .collect()
    }

    /// Put real values back into text that contains tokens (e.g. a model reply).
    fn unmask(&self, text: &str) -> String {
        self.prepared.map.unmask(text).text
    }

    fn __repr__(&self) -> String {
        format!(
            "MaskResult(parser={:?}, tokens={})",
            self.prepared.parser,
            self.prepared.map.len()
        )
    }
}

/// Mask sensitive values in log text. mode is "default" or "strict".
#[pyfunction]
#[pyo3(signature = (text, mode = "default", policy = None, parser = None))]
fn mask(
    text: &str,
    mode: &str,
    policy: Option<PathBuf>,
    parser: Option<&str>,
) -> PyResult<MaskResult> {
    let err = |e: String| PyValueError::new_err(e);
    let mut p = match policy {
        Some(path) => Policy::load(&path).map_err(|e| err(e.to_string()))?,
        None => Policy::default(),
    };
    match mode {
        "default" => {}
        "strict" => p = p.strict(),
        other => {
            return Err(err(format!(
                "mode must be \"default\" or \"strict\", not {other:?}"
            )));
        }
    }
    let engine = Engine::new(p).map_err(|e| err(e.to_string()))?;
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).map_err(|e| err(e.to_string()))?;
    let prepared = engine
        .prepare(text, parser, salt)
        .map_err(|e| err(e.to_string()))?;
    Ok(MaskResult { prepared })
}

/// Names of the available log parsers.
#[pyfunction]
fn parsers() -> Vec<String> {
    sudare_core::parse::Registry::builtin()
        .parsers()
        .map(|p| p.name().to_string())
        .collect()
}

#[pymodule]
fn sudare(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(mask, m)?)?;
    m.add_function(wrap_pyfunction!(parsers, m)?)?;
    m.add_class::<MaskResult>()?;
    Ok(())
}
