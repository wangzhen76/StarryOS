use crate::syscalls::syscall_table::_utee_log;
use core::ffi::*;
use core::fmt::{Arguments, Result, Write};

pub const TRACE_MIN: i32 = 0;
pub const TRACE_ERROR: i32 = 1;
pub const TRACE_INFO: i32 = 2;
pub const TRACE_DEBUG: i32 = 3;
pub const TRACE_FLOW: i32 = 4;
pub const TRACE_MAX: i32 = TRACE_FLOW;
pub const TRACE_PRINTF_LEVEL: i32 = TRACE_ERROR;

pub const DEFAULT_TRACE_LEVEL: i32 = {
    if cfg!(feature = "trace-error") {
        TRACE_ERROR
    } else if cfg!(feature = "trace-flow") {
        TRACE_FLOW
    } else if cfg!(feature = "trace-info") {
        TRACE_INFO
    } else if cfg!(feature = "trace-debug") {
        TRACE_DEBUG
    } else {
        TRACE_MAX
    }
};

use core::sync::atomic::{AtomicI32, Ordering};

static TRACE_LEVEL: AtomicI32 = AtomicI32::new(DEFAULT_TRACE_LEVEL);

pub struct Trace;

impl Trace {
    fn new() -> Self {
        Trace {}
    }

    pub fn _print(fmt: Arguments) {
        let mut writer = Trace::new();
        let result = writer.write_fmt(fmt);

        if let Err(e) = result {
            panic!("failed printing to trace: {}", e);
        }
    }

    pub fn set_level(level: i32) {
        let val = if level >= TRACE_MIN && level <= TRACE_MAX {
            level
        } else {
            TRACE_MAX
        };
        TRACE_LEVEL.store(val, Ordering::Relaxed);
    }

    pub fn get_level() -> i32 {
        TRACE_LEVEL.load(Ordering::Relaxed)
    }
}

impl Write for Trace {
    fn write_str(&mut self, buf: &str) -> Result {
        unsafe {
            _utee_log(buf.as_ptr() as *const c_void, buf.len());
        }
        Ok(())
    }
}
