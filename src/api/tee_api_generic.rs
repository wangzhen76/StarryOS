use crate::{
    tee_api_defines::{
        TEE_NUM_PARAMS, TEE_PARAM_TYPE_GET, TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_INOUT,
        TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT,
    },
    tee_api_types::{Memref, TEE_Param},
    utee_types::utee_params,
};

pub(crate) fn copy_param(
    up: &mut utee_params,
    paramTypes: u32,
    params: *mut [TEE_Param; TEE_NUM_PARAMS as usize],
) {
    up.types = paramTypes as u64;
    let params = unsafe { &mut *params };
    for i in 0..TEE_NUM_PARAMS as usize {
        let (a, b) = match TEE_PARAM_TYPE_GET(paramTypes, i as u32) {
            TEE_PARAM_TYPE_VALUE_INPUT | TEE_PARAM_TYPE_VALUE_INOUT => unsafe {
                (params[i].value.a as u64, params[i].value.b as u64)
            },
            TEE_PARAM_TYPE_MEMREF_OUTPUT
            | TEE_PARAM_TYPE_MEMREF_INOUT
            | TEE_PARAM_TYPE_MEMREF_INPUT => unsafe {
                let memref = params[i].memref;
                let buffer_ptr = memref.buffer as u64;
                (buffer_ptr, memref.size as u64)
            },
            _ => (0, 0),
        };

        up.vals[i * 2] = a;
        up.vals[i * 2 + 1] = b;
    }
}

pub(crate) fn update_out_param(
    params: *mut [TEE_Param; TEE_NUM_PARAMS as usize],
    up: &utee_params,
) {
    let params = unsafe { &mut *params };
    for i in 0..TEE_NUM_PARAMS as usize {
        let a = up.vals[i * 2];
        let b = up.vals[i * 2 + 1];
        match TEE_PARAM_TYPE_GET(up.types as u32, i as u32) {
            TEE_PARAM_TYPE_VALUE_OUTPUT | TEE_PARAM_TYPE_VALUE_INOUT => {
                params[i].value.a = a as u32;
                params[i].value.b = b as u32;
            }
            TEE_PARAM_TYPE_MEMREF_OUTPUT | TEE_PARAM_TYPE_MEMREF_INOUT => {
                params[i].memref = Memref {
                    buffer: a as _,
                    size: b as usize,
                }
            }
            _ => {}
        };
    }
}
