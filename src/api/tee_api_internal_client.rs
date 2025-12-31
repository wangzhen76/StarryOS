use crate::{
    api::{
        tee_api_generic::{copy_param, update_out_param},
        tee_api_panic::TEE_Panic,
    },
    syscalls::syscall_table::{
        _utee_close_ta_session, _utee_invoke_ta_command, _utee_open_ta_session,
    },
    tee_api_defines::{TEE_HANDLE_NULL, TEE_NUM_PARAMS, TEE_SUCCESS},
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

#[unsafe(no_mangle)]
pub extern "C" fn TEE_CloseTASession(session: TEE_TASessionHandle) {
    if session != TEE_HANDLE_NULL as _ {
        let res = unsafe { _utee_close_ta_session(session as _) } as u32;

        if res != TEE_SUCCESS {
            TEE_Panic(res);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn TEE_InvokeTACommand(
    session: TEE_TASessionHandle,
    cancellationRequestTimeout: u32,
    commandID: u32,
    paramTypes: u32,
    params: *mut [TEE_Param; TEE_NUM_PARAMS as usize],
    returnOrigin: *mut u32,
) -> TEE_Result {
    let mut up = utee_params {
        types: 0,
        vals: [0; _],
    };
    copy_param(&mut up, paramTypes, params);
    let res = unsafe {
        _utee_invoke_ta_command(
            session as _,
            cancellationRequestTimeout as _,
            commandID as _,
            session as _,
            returnOrigin as _,
        )
    };
    update_out_param(params, &up);

    res as TEE_Result
}
