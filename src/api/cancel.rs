use crate::{
    syscalls::syscall_table::{
        _utee_get_cancellation_flag, _utee_mask_cancellation, _utee_unmask_cancellation,
    },
    tee_api_defines::TEE_SUCCESS,
};

pub fn TEE_GetCancellationFlag() -> bool {
    let mut flag = 0;
    let res = unsafe { _utee_get_cancellation_flag(&mut flag) };
    if res as u32 != TEE_SUCCESS {
        flag = 0;
    }
    flag != 0
}

pub fn TEE_MaskCancellation() -> bool {
    let mut old_mask = 0;
    let res = unsafe { _utee_mask_cancellation(&mut old_mask) };
    if res as u32 != TEE_SUCCESS {
        //TODO need TEE_Panic
        // TEE_Panic(res);
    }
    old_mask != 0
}

pub fn TEE_UnmaskCancellation() -> bool {
    let mut old_mask = 0;
    let res = unsafe { _utee_unmask_cancellation(&mut old_mask) };
    if res as u32 != TEE_SUCCESS {
        //TODO need TEE_Panic
        // TEE_Panic(res);
    }
    old_mask != 0
}
