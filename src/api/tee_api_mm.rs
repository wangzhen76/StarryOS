use std::ffi::c_void;

use crate::{tee_api_defines::TEE_SUCCESS, tee_api_types::TEE_Result};

pub fn TEE_CheckMemoryAccessRights(
    _accessFlags: u32,
    _buffer: *mut c_void,
    _size: usize,
) -> TEE_Result {
    TEE_SUCCESS
}
