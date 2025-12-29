use crate::{
    tee_api_defines::{
        TEE_NUM_PARAMS, TEE_PARAM_TYPE_GET, TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_INOUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
    },
    tee_api_types::TEE_Param,
    utee_types::utee_params,
};

pub(crate) fn copy_param(
    up: &mut utee_params,
    paramTypes: u32,
    params: &[TEE_Param; TEE_NUM_PARAMS as usize],
) {
    up.types = paramTypes as u64;
    for i in 0..TEE_NUM_PARAMS {
        let (a, b) = match TEE_PARAM_TYPE_GET(paramTypes, i) {
            TEE_PARAM_TYPE_VALUE_INPUT | TEE_PARAM_TYPE_VALUE_INOUT => unsafe {
                (
                    params[i as usize].value.a as u64,
                    params[i as usize].value.b as u64,
                )
            },
            TEE_PARAM_TYPE_MEMREF_OUTPUT
            | TEE_PARAM_TYPE_MEMREF_INOUT
            | TEE_PARAM_TYPE_MEMREF_INPUT => unsafe {
                let memref = params[i as usize].memref;
                let buffer_ptr = memref.buffer as u64;
                (buffer_ptr, memref.size as u64)
            },
            _ => (0, 0),
        };

        up.vals[i as usize * 2] = a;
        up.vals[i as usize * 2 + 1] = b;
    }
}
