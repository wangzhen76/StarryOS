
use crate::tee_api_defines::*;
use crate::tee_api_types::*;
use core::ffi::c_void;
use core::ffi::*;
use core::ptr;
use libc::{memcpy, strlen, free, malloc};
use mbedtls_sys_auto::base64_decode;
use mbedtls_sys_auto::base64_encode;
use std::ptr::null_mut;

use crate::api::user_ta_headers::*;
use crate::syscalls::syscall_table::{_utee_get_property, _utee_get_property_name_to_index};
use crate::api::tee_api_panic::TEE_Panic;
use core::mem;

#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
pub enum UserTaPropType {
    USER_TA_PROP_TYPE_BOOL,         /* bool */
    USER_TA_PROP_TYPE_U32,          /* uint32_t */
    USER_TA_PROP_TYPE_UUID,         /* TEE_UUID */
    USER_TA_PROP_TYPE_IDENTITY,     /* TEE_Identity */
    USER_TA_PROP_TYPE_STRING,       /* zero terminated string of char */
    USER_TA_PROP_TYPE_BINARY_BLOCK, /* zero terminated base64 coded string */
    USER_TA_PROP_TYPE_U64,          /* uint64_t */
    USER_TA_PROP_TYPE_INVALID,      /* invalid value */
}

#[repr(C)]
pub struct UserTaProperty {
    pub name: *const c_uchar,
    pub prop_type: UserTaPropType,
    pub value: *mut c_void,
}

unsafe impl Sync for UserTaProperty {}


#[repr(C)]
struct PropEnumerator {
    idx: u32,
    prop_set: TEE_PropSetHandle,
}

//TODO: this need to be a config option
pub const CFG_TA_BIGNUM_MAX_BITS: u32 = 2048;
pub const TEE_ISOCKET_VERSION: u32 = 0x01000000;
pub const PROP_ENUMERATOR_NOT_STARTED: u32 = 0xffffffff;

pub const TEE_CORE_API_MAJOR_VERSION: u32 = 1;
pub const TEE_CORE_API_MINOR_VERSION: u32 = 3;
pub const TEE_CORE_API_MAINTENANCE_VERSION: u32 = 1;
pub const MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL: i32 = -0x002A_i32;

pub const TEE_CORE_API_VERSION: u32 = (TEE_CORE_API_MAJOR_VERSION << 24)
    | (TEE_CORE_API_MINOR_VERSION << 16)
    | (TEE_CORE_API_MAINTENANCE_VERSION << 8);

#[unsafe(no_mangle)]
pub static tee_props: [UserTaProperty; 4usize] = [
    UserTaProperty {
        name: "gpd.tee.arith.maxBigIntSize".as_ptr(),
        prop_type: UserTaPropType::USER_TA_PROP_TYPE_U32,
        value: CFG_TA_BIGNUM_MAX_BITS as *mut _,
    },
    UserTaProperty {
        name: "gpd.tee.sockets.version".as_ptr(),
        prop_type: UserTaPropType::USER_TA_PROP_TYPE_U32,
        value: TEE_ISOCKET_VERSION as *mut _,
    },
    UserTaProperty {
        name: "gpd.tee.sockets.tcp.version".as_ptr(),
        prop_type: UserTaPropType::USER_TA_PROP_TYPE_U32,
        value: TEE_ISOCKET_VERSION as *mut _,
    },
    UserTaProperty {
        name: "gpd.tee.internalCore.version".as_ptr(),
        prop_type: UserTaPropType::USER_TA_PROP_TYPE_U32,
        value: TEE_CORE_API_VERSION as *mut _,
    },
];

fn is_propset_pseudo_handle(h: TEE_PropSetHandle) -> bool {
    h == TEE_PROPSET_CURRENT_TA
        || h == TEE_PROPSET_CURRENT_CLIENT
        || h == TEE_PROPSET_TEE_IMPLEMENTATION
}

fn propset_get(
    h: TEE_PropSetHandle,
    eps: *mut *const UserTaProperty,
    eps_len: *mut usize,
) -> TEE_Result {
    unsafe {
        match h {
            TEE_PROPSET_CURRENT_TA => {
                *eps = ta_props.as_ptr();
                *eps_len = ta_num_props;
            }
            TEE_PROPSET_CURRENT_CLIENT => {
                *eps = core::ptr::null();
                *eps_len = 0;
            }
            TEE_PROPSET_TEE_IMPLEMENTATION => {
                *eps = ta_props.as_ptr();
                *eps_len = tee_props.len();
            }
            _ => {
                return TEE_ERROR_ITEM_NOT_FOUND;
            }
        }
    }
    TEE_SUCCESS
}

#[inline]
pub unsafe fn base64_dec(
    src: *const libc::c_char,
    src_len: usize,
    dst: *mut u8,
    dst_len: &mut usize,
) -> bool {
    let mut out_len: usize = 0;

    let ret = base64_decode(dst, *dst_len, &mut out_len, src as *const u8, src_len);

    *dst_len = out_len;

    ret == 0 || ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL
}


#[inline]
pub unsafe fn base64_enc(
    src: *const c_char,
    src_len: usize,
    dst: *mut u8,
    dst_len: &mut usize,
) -> bool {
    let mut out_len: usize = 0;

    let ret = base64_encode(dst, *dst_len, &mut out_len, src as *const u8, src_len);

    *dst_len = out_len;

    ret == 0 || ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL
}


unsafe fn propget_get_ext_prop(
    prop: *const UserTaProperty,
    prop_type: *mut UserTaPropType,
    buf: *mut c_void,
    len: *mut c_uint,
) -> TEE_Result {
    let prop = &*prop;
    *prop_type = prop.prop_type;
    let mut l: usize = match prop.prop_type {
        UserTaPropType::USER_TA_PROP_TYPE_BOOL => mem::size_of::<bool>(),
        UserTaPropType::USER_TA_PROP_TYPE_U32 => mem::size_of::<u32>(),
        UserTaPropType::USER_TA_PROP_TYPE_UUID => mem::size_of::<TEE_UUID>(),
        UserTaPropType::USER_TA_PROP_TYPE_U64 => mem::size_of::<u64>(),
        UserTaPropType::USER_TA_PROP_TYPE_IDENTITY => mem::size_of::<TEE_Identity>(),
        UserTaPropType::USER_TA_PROP_TYPE_STRING => strlen(prop.value as *const c_char) + 1,
        UserTaPropType::USER_TA_PROP_TYPE_BINARY_BLOCK => {
            let mut out_len = *len as usize;
            let ok = base64_dec(
                prop.value as *const c_char,
                strlen(prop.value as *const c_char),
                buf as *mut u8,
                &mut out_len,
            );
            if !ok && out_len <= (*len as usize) {
                return TEE_ERROR_GENERIC;
            }
            if (*len as usize) < out_len {
                *len = out_len as u32;
                return TEE_ERROR_SHORT_BUFFER;
            }
            *len = out_len as u32;
            TEE_SUCCESS as usize
        }
        _ => TEE_ERROR_GENERIC as usize,
    };
    if (*len as usize) < l {
        *len = l as u32;
        return TEE_ERROR_SHORT_BUFFER;
    }
    *len = l as u32;
    memcpy(buf, prop.value, l);
    TEE_SUCCESS
}

unsafe fn propget_get_property(
    h: TEE_PropSetHandle,
    name: *const c_char,
    prop_type_out: *mut UserTaPropType,
    buf: *mut c_void,
    len: *mut c_uint,
) -> TEE_Result {
    let mut eps: *const UserTaProperty = core::ptr::null();
    let mut eps_len: usize = 0;
    let mut prop_type: u32 = 0;
    let mut index: u32 = 0;

    if is_propset_pseudo_handle(h) {
        let res = propset_get(h, &mut eps, &mut eps_len);
        if res != TEE_SUCCESS {
            return res;
        }
        for n in 0..eps_len {
            let prop = &*eps.add(n);
            if core::ptr::eq(name, prop.name) {
                return propget_get_ext_prop(prop, prop_type_out, buf, len);
            }
        }

        let res =
            _utee_get_property_name_to_index(h as u64, name as *const c_void, strlen(name) as u64 + 1, &mut index);
        if res != (TEE_SUCCESS as usize) {
            return res as u32;
        }

        let res = _utee_get_property(
            h as u64,
            index as u64,
            null_mut(),
            null_mut(),
            buf,
            len,
            &mut prop_type,
        );

        if prop_type_out.is_null() {
            return res as u32;
        }

        *prop_type_out = core::mem::transmute(prop_type);
        return res as u32;
    }

    let pe = &*(h as *const PropEnumerator);
    let mut idx = pe.idx;
    if idx == PROP_ENUMERATOR_NOT_STARTED {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    let res = propset_get(pe.prop_set, &mut eps, &mut eps_len);
    if res != TEE_SUCCESS {
        return res;
    }

    if (idx as usize) < eps_len {
        return propget_get_ext_prop(
            &*eps.add(idx as usize),
            prop_type_out,
            buf,
            len
        );
    }
    idx -= eps_len as u32;

    let res = _utee_get_property(
        pe.prop_set as u64,
        idx as u64,
        null_mut(),
        null_mut(),
        buf,
        len,
        &mut prop_type,
    );

    let res = if res == (TEE_ERROR_ITEM_NOT_FOUND as usize) {
        TEE_ERROR_BAD_PARAMETERS
    } else {
        res as u32
    };

    if !prop_type_out.is_null() {
        *prop_type_out = core::mem::transmute(prop_type);
    }

    res
}

fn handle_result(res: TEE_Result, tmp_buf: *mut c_void) -> TEE_Result {
    if !tmp_buf.is_null() {
        unsafe {free(tmp_buf);}
    }
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_SHORT_BUFFER &&
       res != TEE_ERROR_ITEM_NOT_FOUND {
        TEE_Panic(0);
    }
    res
}
fn base64_enc_len(n: usize) -> usize {
    let enc = ((n + 2) / 3) * 4;
    enc + 1
}




fn copy_string(src: &str, dst: *mut u8) -> Result<usize, ()> {
    
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
    }
    
    Ok(src.len())
}


pub unsafe extern "C" fn TEE_GetPropertyAsString(
    propset_or_enumerator: TEE_PropSetHandle,
    name: *const c_char,
    value: *mut c_char,
    value_len: *mut usize,
) -> TEE_Result {
    
    let mut res = TEE_ERROR_GENERIC;
    let mut tmp_buf = core::ptr::null_mut();

    let tmp_len = if *value_len < mem::size_of::<TEE_Identity>() {
        mem::size_of::<TEE_Identity>()
    } else {
        *value_len
    };
    tmp_buf = unsafe { malloc(tmp_len) };
    if tmp_buf.is_null() {
        res = TEE_ERROR_OUT_OF_MEMORY;
        return handle_result(res, tmp_buf);
    }
    
    let mut tmp_len_var: u32 = tmp_len as u32;
    let mut prop_type = UserTaPropType::USER_TA_PROP_TYPE_INVALID;
    res = propget_get_property(
        propset_or_enumerator,
        name,
        &mut prop_type,
        tmp_buf,
        &mut tmp_len_var,
    );
    if res != TEE_SUCCESS {
        if res == TEE_ERROR_SHORT_BUFFER {
            if prop_type == UserTaPropType::USER_TA_PROP_TYPE_BINARY_BLOCK {
                *value_len = base64_enc_len(tmp_len_var as usize);
            } else {
                *value_len = tmp_len_var as usize;

            }
        }
        return handle_result(res, tmp_buf);
    }

    let l = match prop_type {
        UserTaPropType::USER_TA_PROP_TYPE_BOOL => {
            let bool_value = *(tmp_buf as *const bool);
            let s = if bool_value {
                "true"
            } else {
                "false"
            };
            copy_string(s, value).unwrap()
        },
        UserTaPropType::USER_TA_PROP_TYPE_U32 => {
            let u32_value = *(tmp_buf as *const u32);
            copy_string(&format!("{}",u32_value), value).unwrap()
        },
        UserTaPropType::USER_TA_PROP_TYPE_UUID => {
            let uuid_value = *(tmp_buf as *const TEE_UUID);
            copy_string(&format!("{}",uuid_value), value).unwrap()
        },
        UserTaPropType::USER_TA_PROP_TYPE_IDENTITY => {
            let identity_value = *(tmp_buf as *const TEE_Identity);
            copy_string(&format!("{}:{}",identity_value.login,identity_value.uuid), value).unwrap()
        },
        UserTaPropType::USER_TA_PROP_TYPE_STRING => {
            let string_value = *(tmp_buf as *const *const c_char);
            let c_string_value = unsafe { CStr::from_ptr(string_value).to_str().unwrap() };
         
            copy_string(c_string_value, value).unwrap()
        },
        UserTaPropType::USER_TA_PROP_TYPE_BINARY_BLOCK => {
            let mut tmp_l = *value_len;
            if !base64_enc(tmp_buf as *mut c_char, tmp_len, value, &mut tmp_l) && tmp_l <= *value_len {
               res = TEE_ERROR_GENERIC;
               return handle_result(res, tmp_buf);
            }
            tmp_l
        },
        _ => {
            res = TEE_ERROR_BAD_FORMAT;
            return handle_result(res, tmp_buf);
        }
    };

    if l > *value_len {
        res = TEE_ERROR_SHORT_BUFFER;
    }
    *value_len = l;
    handle_result(res, tmp_buf)
}

