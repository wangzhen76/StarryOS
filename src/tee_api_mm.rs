use std::ffi::c_void;

use crate::tee_api_types::TEE_Result;

pub fn TEE_CheckMemoryAccessRights(
    accessFlags: u32,
    buffer: *mut c_void,
    size: usize,
) -> TEE_Result {
    unimplemented!()
}
