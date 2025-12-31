// Auto-generated syscall table using define_utee_syscalls!
// Parameter types use primitive usize/pointer-friendly types to avoid
// tight coupling with api type definitions in other modules.
use crate::tee_api_types::*;
use core::ffi::*;
pub type size_t = usize;
use crate::utee_types::*;

// arity 0
crate::define_utee_syscalls! {
    TEE_SCN_SE_SERVICE_OPEN__DEPRECATED = 55 => fn _utee_se_service_open__deprecated();
}

// arity 1
crate::define_utee_syscalls! {
    TEE_SCN_CLOSE_TA_SESSION = 6 => fn _utee_close_ta_session(sess: c_ulong);
    TEE_SCN_GET_CANCELLATION_FLAG = 9 => fn _utee_get_cancellation_flag(cancel: *mut u32);
    TEE_SCN_UNMASK_CANCELLATION = 10 => fn _utee_unmask_cancellation(old_mask: *mut u32);
    TEE_SCN_MASK_CANCELLATION = 11 => fn _utee_mask_cancellation(old_mask: *mut u32);
    TEE_SCN_WAIT = 12 => fn _utee_wait(timeout: c_ulong);
    TEE_SCN_SET_TA_TIME = 14 => fn _utee_set_ta_time(time: *const TEE_Time);
    TEE_SCN_CRYP_STATE_FREE = 17 => fn _utee_cryp_state_free(state: c_ulong);
    TEE_SCN_CRYP_OBJ_CLOSE = 28 => fn _utee_cryp_obj_close(obj: c_ulong);
    TEE_SCN_CRYP_OBJ_RESET = 29 => fn _utee_cryp_obj_reset(obj: c_ulong);
    TEE_SCN_STORAGE_OBJ_DEL = 43 => fn _utee_storage_obj_del(obj: c_ulong);
    TEE_SCN_STORAGE_ENUM_ALLOC = 45 => fn _utee_storage_alloc_enum(obj_enum: *mut u32);
    TEE_SCN_STORAGE_ENUM_FREE = 46 => fn _utee_storage_free_enum(obj_enum: c_ulong);
    TEE_SCN_STORAGE_ENUM_RESET = 47 => fn _utee_storage_reset_enum(obj_enum: c_ulong);
}

// arity 2
crate::define_utee_syscalls! {
    TEE_SCN_GET_TIME = 13 => fn _utee_get_time(cat: c_ulong, time: *mut TEE_Time);
    TEE_SCN_CRYP_STATE_COPY = 16 => fn _utee_cryp_state_copy(dst: c_ulong, src: c_ulong);
    TEE_SCN_CRYP_OBJ_GET_INFO = 24 => fn _utee_cryp_obj_get_info(obj: c_ulong, info: *mut utee_object_info);
    TEE_SCN_CRYP_OBJ_RESTRICT_USAGE = 25 => fn _utee_cryp_obj_restrict_usage(obj: c_ulong, usage: c_ulong);
    TEE_SCN_CRYP_OBJ_COPY = 31 => fn _utee_cryp_obj_copy(dst_obj: c_ulong, src_obj: c_ulong);
    TEE_SCN_CRYP_RANDOM_NUMBER_GENERATE = 33 => fn _utee_cryp_random_number_generate(buf: *mut c_void, blen: size_t);
    TEE_SCN_STORAGE_ENUM_START = 48 => fn _utee_storage_start_enum(obj_enum: c_ulong, storage_id: c_ulong);
    TEE_SCN_STORAGE_OBJ_TRUNC = 52 => fn _utee_storage_obj_trunc(obj: c_ulong, len: size_t);
}

// arity 3
crate::define_utee_syscalls! {
    TEE_SCN_CHECK_ACCESS_RIGHTS = 8 => fn _utee_check_access_rights(flags: u32, buf: *const c_void, len: size_t);
    TEE_SCN_HASH_INIT = 18 => fn _utee_hash_init(state: c_ulong, iv: *const c_void, iv_len: size_t);
    TEE_SCN_HASH_UPDATE = 19 => fn _utee_hash_update(state: c_ulong, chunk: *const c_void, chunk_size: size_t);
    TEE_SCN_CIPHER_INIT = 21 => fn _utee_cipher_init(state: c_ulong, iv: *const c_void, iv_len: size_t);
    TEE_SCN_CRYP_OBJ_ALLOC = 27 => fn _utee_cryp_obj_alloc(ttype: c_ulong, max_size: c_ulong, obj: *mut u32);
    TEE_SCN_CRYP_OBJ_POPULATE = 30 => fn _utee_cryp_obj_populate(obj: c_ulong, attrs: *mut utee_attribute, attr_count: c_ulong);
    TEE_SCN_AUTHENC_UPDATE_AAD = 35 => fn _utee_authenc_update_aad(state: c_ulong, aad_data: *const c_void, aad_data_len: size_t);
    TEE_SCN_STORAGE_OBJ_RENAME = 44 => fn _utee_storage_obj_rename(obj: c_ulong, new_obj_id: *const c_void, new_obj_id_len: size_t);
    TEE_SCN_STORAGE_OBJ_WRITE = 51 => fn _utee_storage_obj_write(obj: c_ulong, data: *const c_void, len: size_t);
    TEE_SCN_STORAGE_OBJ_SEEK = 53 => fn _utee_storage_obj_seek(obj: c_ulong, offset: i32, whence: c_ulong);
    TEE_SCN_CACHE_OPERATION = 70 => fn _utee_cache_operation(va: *mut c_void, l: size_t, op: c_ulong);
}

// arity 4
crate::define_utee_syscalls! {
    TEE_SCN_GET_PROPERTY_NAME_TO_INDEX = 4 => fn _utee_get_property_name_to_index(prop_set: c_ulong, name: *const c_void, name_len: c_ulong, index: *mut u32);
    TEE_SCN_CRYP_OBJ_GET_ATTR = 26 => fn _utee_cryp_obj_get_attr(obj: c_ulong, attr_id: c_ulong, buffer: *mut c_void, size: *mut u64);
    TEE_SCN_STORAGE_ENUM_NEXT = 49 => fn _utee_storage_next_enum(obj_enum: c_ulong, info: *mut utee_object_info, obj_id: *mut c_void, len: *mut u64);
    TEE_SCN_STORAGE_OBJ_READ = 50 => fn _utee_storage_obj_read(obj: c_ulong, data: *mut c_void, len: size_t, count: *mut u64);
    TEE_SCN_CRYP_OBJ_GENERATE_KEY = 54 => fn _utee_cryp_obj_generate_key(obj: c_ulong, key_size: c_ulong, params: *const utee_attribute, param_count: c_ulong);
}

// arity 5
crate::define_utee_syscalls! {
    TEE_SCN_OPEN_TA_SESSION = 5 => fn _utee_open_ta_session(dest: *const TEE_UUID, cancel_req_to: c_ulong, params: *mut utee_params, sess: *mut u32, ret_orig: *mut u32);
    TEE_SCN_INVOKE_TA_COMMAND = 7 => fn _utee_invoke_ta_command(sess: c_ulong, cancel_req_to: c_ulong, cmd_id: c_ulong, params: *mut utee_params, ret_orig: *mut u32);
    TEE_SCN_CRYP_STATE_ALLOC = 15 => fn _utee_cryp_state_alloc(algo: c_ulong, op_mode: c_ulong, key1: c_ulong, key2: c_ulong, state: *mut u32);
    TEE_SCN_HASH_FINAL = 20 => fn _utee_hash_final(state: c_ulong, chunk: *const c_void, chunk_size: size_t, hash: *mut c_void, hash_len: *mut u64);
    TEE_SCN_CIPHER_UPDATE = 22 => fn _utee_cipher_update(state: c_ulong, src: *const c_void, src_len: size_t, dest: *mut c_void, dest_len: *mut u64);
    TEE_SCN_CIPHER_FINAL = 23 => fn _utee_cipher_final(state: c_ulong, src: *const c_void, src_len: size_t, dest: *mut c_void, dest_len: *mut u64);
    TEE_SCN_AUTHENC_UPDATE_PAYLOAD = 36 => fn _utee_authenc_update_payload(state: c_ulong, src_data: *const c_void, src_len: size_t, dest_data: *mut c_void, dest_len: *mut u64);
    TEE_SCN_STORAGE_OBJ_OPEN = 41 => fn _utee_storage_obj_open(storage_id: c_ulong, object_id: *const c_void, object_id_len: size_t, flags: c_ulong, obj: *mut u32);
}

// arity 6
crate::define_utee_syscalls! {
    TEE_SCN_AUTHENC_INIT = 34 => fn _utee_authenc_init(state: c_ulong, nonce: *const c_void, nonce_len: size_t, tag_len: size_t, aad_len: size_t, payload_len: size_t);
}

// arity 7
crate::define_utee_syscalls! {
    TEE_SCN_GET_PROPERTY = 3 => fn _utee_get_property(prop_set: c_ulong, index: c_ulong, name: *mut c_void, name_len: *mut u32, buf: *mut c_void, blen: *mut u32, prop_type: *mut u32);
    TEE_SCN_AUTHENC_ENC_FINAL = 37 => fn _utee_authenc_enc_final(state: c_ulong, src_data: *const c_void, src_len: size_t, dest_data: *mut c_void, dest_len: *mut u64, tag: *mut c_void, tag_len: *mut u64);
    TEE_SCN_AUTHENC_DEC_FINAL = 38 => fn _utee_authenc_dec_final(state: c_ulong, src_data: *const c_void, src_len: size_t, dest_data: *mut c_void, dest_len: *mut u64, tag: *const c_void, tag_len: size_t);
    TEE_SCN_ASYMM_OPERATE = 39 => fn _utee_asymm_operate(state: c_ulong, params: *const utee_attribute, num_params: c_ulong, src_data: *const c_void, src_len: size_t, dest_data: *mut c_void, dest_len: *mut u64);
    TEE_SCN_ASYMM_VERIFY = 40 => fn _utee_asymm_verify(state: c_ulong, params: *const utee_attribute, num_params: c_ulong, data: *const c_void, data_len: size_t, sig: *const c_void, sig_len: size_t);
}

// arity 8
crate::define_utee_syscalls! {
    TEE_SCN_STORAGE_OBJ_CREATE = 42 => fn _utee_storage_obj_create(storage_id: c_ulong, object_id: *const c_void, object_id_len: size_t, flags: c_ulong, attr: c_ulong, data: *const c_void, len: size_t, obj: *mut u32);
}

pub const TEE_SCN_RETURN: usize = 0;
pub extern "C" fn _utee_return(ret: c_ulong) -> ! {
    unsafe {
        core::arch::asm!("svc #0", in("x8") TEE_SCN_RETURN + 500, in("x0") ret, options(nostack));
        panic!("error");
    }
}

pub const TEE_SCN_LOG: usize = 1;
pub extern "C" fn _utee_log(buf: *const c_void, len: size_t) {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") TEE_SCN_LOG + 500,
            in("x0") buf,
            in("x1") len,
            options(nostack)
        );
    }
}

pub const TEE_SCN_PANIC: usize = 2;
pub extern "C" fn _utee_panic(code: c_ulong) {
    unsafe {
        core::arch::asm!("svc #0", in("x8") TEE_SCN_PANIC + 500, in("x0") code, options(nostack));
        panic!("error");
    }
}
