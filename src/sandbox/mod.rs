#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(not(target_os = "linux"), path = "unsupported.rs")]
mod sandbox_impl;

use pyo3::{create_exception, exceptions::PyException, prelude::*, types::PyTuple};

#[derive(Clone, Debug)]
pub enum AccessFS {
    Read(String),
    ReadWrite(String),
    MakeReg(String),
    MakeDir(String),
}

/// Enforces access restrictions
#[pyfunction(name = "restrict_access", signature=(*rules))]
fn py_restrict_access(rules: &PyTuple) -> PyResult<()> {
    sandbox_impl::restrict_access(
        &rules
            .iter()
            .map(|r| Ok(r.extract::<PyAccessFS>()?.access))
            .collect::<PyResult<Vec<_>>>()?,
    )
    .map_err(|err| SandboxError::new_err(err.to_string()))
}

create_exception!(unblob_native.sandbox, SandboxError, PyException);

#[pyclass(name = "AccessFS", module = "unblob_native.sandbox")]
#[derive(Clone)]
struct PyAccessFS {
    access: AccessFS,
}

impl PyAccessFS {
    fn new(access: AccessFS) -> Self {
        Self { access }
    }
}

#[pymethods]
impl PyAccessFS {
    #[staticmethod]
    fn read(dir: String) -> Self {
        Self::new(AccessFS::Read(dir))
    }

    #[staticmethod]
    fn read_write(dir: String) -> Self {
        Self::new(AccessFS::ReadWrite(dir))
    }

    #[staticmethod]
    fn make_reg(dir: String) -> Self {
        Self::new(AccessFS::MakeReg(dir))
    }

    #[staticmethod]
    fn make_dir(dir: String) -> Self {
        Self::new(AccessFS::MakeDir(dir))
    }
}

pub fn init_module(py: Python, root_module: &PyModule) -> PyResult<()> {
    let module = PyModule::new(py, "sandbox")?;
    module.add_function(wrap_pyfunction!(py_restrict_access, module)?)?;
    module.add_class::<PyAccessFS>()?;

    root_module.add_submodule(module)?;

    let sys = PyModule::import(py, "sys")?;
    let modules = sys.getattr("modules")?;
    modules.call_method(
        "__setitem__",
        ("unblob_native.sandbox".to_string(), module),
        None,
    )?;

    Ok(())
}
