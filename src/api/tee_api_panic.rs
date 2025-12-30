use crate::{syscalls::syscall_table::_utee_panic, tee_api_types::TEE_Result};

#[unsafe(no_mangle)]
pub extern "C" fn TEE_Panic(panic_code: TEE_Result) {
    unsafe {
        _utee_panic(panic_code as u64);
    }
}
