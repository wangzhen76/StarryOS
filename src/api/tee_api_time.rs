use crate::{
    syscalls::syscall_table::{
        _utee_get_time, _utee_wait, _utee_set_ta_time,_utee_panic,
    },
};
use crate::tee_api_defines::{TEE_ERROR_OVERFLOW,TEE_ERROR_TIME_NOT_SET,
    TEE_ERROR_TIME_NEEDS_RESET,TEE_ERROR_OUT_OF_MEMORY,TEE_ERROR_CANCEL,
    TEE_ERROR_STORAGE_NO_SPACE,TEE_SUCCESS};
use crate::tee_api_types::{TEE_Result,TEE_Time};
use crate::utee_types::utee_time_category;




#[unsafe(no_mangle)]
pub extern "C" fn TEE_Panic(panic_code: TEE_Result) {
    unsafe {
        _utee_panic(panic_code as u64);
    }
}


#[unsafe(no_mangle)]
pub extern "C" fn TEE_GetSystemTime(time: *mut TEE_Time) {
    let res = unsafe { _utee_get_time(utee_time_category::UTEE_TIME_CAT_SYSTEM as u64, time) };

    // 检查结果是否为 TEE_SUCCESS (0)
    if res != TEE_SUCCESS as usize {
        TEE_Panic(res as TEE_Result);
    }
}


#[unsafe(no_mangle)]
pub extern "C" fn TEE_GetTAPersistentTime(time: *mut TEE_Time) -> TEE_Result {
    let res = unsafe { _utee_get_time(utee_time_category::UTEE_TIME_CAT_TA_PERSISTENT as u64, time) };
    
    // 如果结果不是成功且不是溢出错误，则将时间设置为0
    if res != TEE_ERROR_OVERFLOW as usize {
        unsafe {
            (*time).seconds = 0;
            (*time).millis = 0;
        }
    }
    
    // 检查是否需要panic
    if res != TEE_SUCCESS as usize &&
       res != TEE_ERROR_TIME_NOT_SET as usize &&
       res != TEE_ERROR_TIME_NEEDS_RESET as usize &&
       res != TEE_ERROR_OVERFLOW as usize &&
       res != TEE_ERROR_OUT_OF_MEMORY as usize {
        TEE_Panic(res as TEE_Result);
    }
    
    res as TEE_Result
}


#[unsafe(no_mangle)]
pub extern "C" fn TEE_GetREETime(time: *mut TEE_Time) {
    let res = unsafe { _utee_get_time(utee_time_category::UTEE_TIME_CAT_REE as u64, time) };

    if res != TEE_SUCCESS as usize {
        TEE_Panic(res as TEE_Result);
    }
}


#[unsafe(no_mangle)]
pub extern "C" fn TEE_Wait(timeout: u32) -> TEE_Result {
    let res = unsafe { _utee_wait(timeout as u64) };

    if res != TEE_SUCCESS as usize && res != TEE_ERROR_CANCEL as usize {
        TEE_Panic(res as TEE_Result);
    }

    res as TEE_Result
}


#[unsafe(no_mangle)]
pub extern "C" fn TEE_SetTAPersistentTime(time: *const TEE_Time) -> TEE_Result {
    let res = unsafe { _utee_set_ta_time(time) };

    if res != TEE_SUCCESS as usize &&
       res != TEE_ERROR_OUT_OF_MEMORY as usize &&
       res != TEE_ERROR_STORAGE_NO_SPACE as usize {
        TEE_Panic(res as TEE_Result);
    }

    res as TEE_Result
}

