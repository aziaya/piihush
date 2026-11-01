//! PyO3 bindings. Python strings are borrowed, never copied, and the GIL is
//! released for all scanning.

use std::borrow::Cow;
use std::collections::BTreeMap;

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

use crate::engine::{self, MaskerConfig};
use crate::rules::ENTITIES;

/// One detected entity. `start` and `end` index into the Python string.
#[pyclass(frozen, eq, module = "piihush._core", get_all)]
#[derive(PartialEq)]
struct Match {
    entity: String,
    start: usize,
    end: usize,
    text: String,
}

#[pymethods]
impl Match {
    #[new]
    fn new(entity: String, start: usize, end: usize, text: String) -> Self {
        Self {
            entity,
            start,
            end,
            text,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Match(entity={:?}, start={}, end={}, text=<{} chars>)",
            self.entity,
            self.start,
            self.end,
            self.end - self.start
        )
    }
}

#[pyclass(frozen, name = "Masker", module = "piihush._core")]
struct PyMasker {
    inner: engine::Masker,
    config: MaskerConfig,
}

fn to_value_error(err: engine::ConfigError) -> PyErr {
    PyValueError::new_err(err.to_string())
}

fn borrow_texts<'a>(texts: &'a [Bound<'_, PyString>]) -> PyResult<Vec<&'a str>> {
    texts.iter().map(|t| t.to_str()).collect()
}

#[pymethods]
impl PyMasker {
    #[new]
    #[pyo3(signature = (
        entities = None,
        *,
        custom_patterns = None,
        deny_list = None,
        allow_list = None,
        template = None,
    ))]
    fn new(
        entities: Option<Vec<String>>,
        custom_patterns: Option<BTreeMap<String, String>>,
        deny_list: Option<BTreeMap<String, Vec<String>>>,
        allow_list: Option<Vec<String>>,
        template: Option<String>,
    ) -> PyResult<Self> {
        let defaults = MaskerConfig::default();
        let config = MaskerConfig {
            entities: entities.unwrap_or(defaults.entities),
            custom_patterns: custom_patterns.into_iter().flatten().collect(),
            deny_list: deny_list.into_iter().flatten().collect(),
            allow_list: allow_list.unwrap_or_default(),
            template: template.unwrap_or(defaults.template),
        };
        let inner = engine::Masker::new(&config).map_err(to_value_error)?;
        Ok(Self { inner, config })
    }

    /// Return `text` with every detected entity replaced by its placeholder.
    fn mask<'py>(&self, text: &Bound<'py, PyString>) -> PyResult<Bound<'py, PyString>> {
        let py = text.py();
        let source = text.to_str()?;
        Ok(match py.detach(|| self.inner.mask(source)) {
            Cow::Borrowed(_) => text.clone(),
            Cow::Owned(masked) => PyString::new(py, &masked),
        })
    }

    /// Mask many documents, in parallel when the batch is large enough.
    fn mask_batch<'py>(
        &self,
        py: Python<'py>,
        texts: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyList>> {
        if texts.is_instance_of::<PyString>() {
            return Err(PyTypeError::new_err(
                "mask_batch() takes an iterable of str, not a single str",
            ));
        }
        let items = texts
            .try_iter()?
            .map(|item| Ok(item?.cast_into::<PyString>()?))
            .collect::<PyResult<Vec<_>>>()?;
        let sources = borrow_texts(&items)?;
        let masked = py.detach(|| self.inner.mask_batch(&sources));
        let out = masked.into_iter().zip(&items).map(|(m, item)| match m {
            Cow::Borrowed(_) => item.clone(),
            Cow::Owned(masked) => PyString::new(py, &masked),
        });
        PyList::new(py, out)
    }

    /// Return the entities found in `text`, without changing it.
    fn detect(&self, text: &Bound<'_, PyString>) -> PyResult<Vec<Match>> {
        let source = text.to_str()?;
        let spans = text.py().detach(|| self.inner.detect(source));
        let ascii = source.is_ascii();
        let (mut byte_pos, mut char_pos) = (0, 0);
        let mut char_offset = |byte: usize| {
            if ascii {
                return byte;
            }
            char_pos += source[byte_pos..byte].chars().count();
            byte_pos = byte;
            char_pos
        };
        Ok(spans
            .iter()
            .map(|span| Match {
                entity: self.inner.label(span).to_owned(),
                start: char_offset(span.start),
                end: char_offset(span.end),
                text: source[span.start..span.end].to_owned(),
            })
            .collect())
    }

    fn __repr__(&self) -> String {
        format!("Masker(entities={:?})", self.config.entities)
    }

    fn __getnewargs_ex__<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<((Vec<String>,), Bound<'py, PyDict>)> {
        let kwargs = PyDict::new(py);
        let patterns: BTreeMap<_, _> = self.config.custom_patterns.iter().cloned().collect();
        let deny: BTreeMap<_, _> = self.config.deny_list.iter().cloned().collect();
        kwargs.set_item("custom_patterns", patterns)?;
        kwargs.set_item("deny_list", deny)?;
        kwargs.set_item("allow_list", self.config.allow_list.clone())?;
        kwargs.set_item("template", self.config.template.clone())?;
        Ok(((self.config.entities.clone(),), kwargs))
    }
}

#[pymodule(gil_used = false)]
fn _core(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyMasker>()?;
    module.add_class::<Match>()?;
    module.add("ENTITIES", ENTITIES.to_vec())?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
