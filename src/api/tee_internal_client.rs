use crate::{
    api::tee_api_generic::{copy_param, update_out_param},
    syscalls::syscall_table::_utee_open_ta_session,
    tee_api_defines::TEE_NUM_PARAMS,
    tee_api_types::{TEE_Param, TEE_Result, TEE_TASessionHandle, TEE_UUID},
    utee_types::utee_params,
};

#[unsafe(no_mangle)]
pub extern "C" fn TEE_OpenTASession(
    destination: *const TEE_UUID,
    cancellationRequestTimeout: u32,
    paramTypes: u32,
    params: *mut [TEE_Param; TEE_NUM_PARAMS as usize],
    session: *mut TEE_TASessionHandle,
    returnOrigin: *mut u32,
) -> TEE_Result {
    let mut up = utee_params {
        types: 0,
        vals: [0; _],
    };
    copy_param(&mut up, paramTypes, params);
    let res = unsafe {
        _utee_open_ta_session(
            destination,
            cancellationRequestTimeout as _,
            &mut up as _,
            session as _,
            returnOrigin as _,
        )
    };
    update_out_param(params, &up);

    res as TEE_Result
}
