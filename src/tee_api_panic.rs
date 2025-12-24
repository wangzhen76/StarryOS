use std::ffi::c_void;

use crate::{
    tee_api_defines::{TEE_ERROR_SECURITY, TEE_SUCCESS},
    tee_api_mm::TEE_CheckMemoryAccessRights,
    tee_api_types::TEE_Result,
};

#[unsafe(no_mangle)]
pub extern "C" fn TEE_PANIC(panicCode: u32) -> ! {
    unimplemented!()
}

fn check_res(msg: &str, res: u32) {
    if res != 0 {
        eprintln!("{}: error {:#010x}", msg, res);
        TEE_PANIC(0);
    }
}

fn check_access(flags: u32, buf: *mut c_void, len: usize) -> TEE_Result {
    if len == 0 {
        return TEE_SUCCESS;
    }

    if buf.is_null() {
        return TEE_ERROR_SECURITY;
    }

    if cfg!(feature = "strict_annotation_checks") {
        return TEE_CheckMemoryAccessRights(flags, buf, len);
    }

    TEE_SUCCESS
}
