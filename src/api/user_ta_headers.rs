use super::tee_api_property::{UserTaPropType, UserTaProperty};
use core::ffi::*;

pub const TA_PROP_STR_SINGLE_INSTANCE: *const c_uchar = "gpd.ta.singleInstance\0".as_ptr();
pub const TA_PROP_STR_MULTI_SESSION: *const c_uchar = "gpd.ta.multiSession\0".as_ptr();
pub const TA_PROP_STR_KEEP_ALIVE: *const c_uchar = "gpd.ta.instanceKeepAlive\0".as_ptr();
pub const TA_PROP_STR_DATA_SIZE: *const c_uchar = "gpd.ta.dataSize\0".as_ptr();
pub const TA_PROP_STR_STACK_SIZE: *const c_uchar = "gpd.ta.stackSize\0".as_ptr();
pub const TA_PROP_STR_VERSION: *const c_uchar = "gpd.ta.version\0".as_ptr();
pub const TA_PROP_STR_DESCRIPTION: *const c_uchar = "gpd.ta.description\0".as_ptr();
pub const TA_PROP_STR_UNSAFE_PARAM: *const c_uchar = "op-tee.unsafe_param\0".as_ptr();
pub const TA_PROP_STR_REMAP: *const c_uchar = "op-tee.remap\0".as_ptr();
pub const TA_PROP_STR_CACHE_SYNC: *const c_uchar = "op-tee.cache_sync\0".as_ptr();

pub const TA_FLAG_SINGLE_INSTANCE: u32 = 1 << 2;
pub const TA_FLAG_MULTI_SESSION: u32 = 1 << 3;
pub const TA_FLAG_INSTANCE_KEEP_ALIVE: u32 = 1 << 4;
pub const TA_FLAG_SECURE_DATA_PATH: u32 = 1 << 5;
pub const TA_FLAG_REMAP_SUPPORT: u32 = 1 << 6;
pub const TA_FLAG_CACHE_MAINTENANCE: u32 = 1 << 7;

const TA_FLAGS: u32 = 0u32;
const TA_DATA_SIZE: u32 = 32768u32;
const TA_STACK_SIZE: u32 = 2048u32;
const TA_VERSION: &[u8] = b"0.4.0\0";
const TA_DESCRIPTION: &[u8] = b"An example of Rust OP-TEE TrustZone SDK.\0";

static FLAG_BOOL: bool = (TA_FLAGS & TA_FLAG_SINGLE_INSTANCE) != 0;
static FLAG_MULTI: bool = (TA_FLAGS & TA_FLAG_MULTI_SESSION) != 0;
static FLAG_INSTANCE: bool = (TA_FLAGS & TA_FLAG_INSTANCE_KEEP_ALIVE) != 0;

#[unsafe(no_mangle)]
pub static ta_num_props: usize = 7usize;
#[unsafe(no_mangle)]
pub static ta_props: [UserTaProperty; 7usize] = [
    UserTaProperty {
        name: TA_PROP_STR_SINGLE_INSTANCE,
        prop_type: UserTaPropType::USER_TA_PROP_TYPE_BOOL,
        value: &FLAG_BOOL as *const bool as *mut _,
    },
    UserTaProperty {
        name: TA_PROP_STR_MULTI_SESSION,
        prop_type: UserTaPropType::USER_TA_PROP_TYPE_BOOL,
        value: &FLAG_MULTI as *const bool as *mut _,
    },
    UserTaProperty {
        name: TA_PROP_STR_KEEP_ALIVE,
        prop_type: UserTaPropType::USER_TA_PROP_TYPE_BOOL,
        value: &FLAG_INSTANCE as *const bool as *mut _,
    },
    UserTaProperty {
        name: TA_PROP_STR_DATA_SIZE,
        prop_type: UserTaPropType::USER_TA_PROP_TYPE_U32,
        value: &TA_DATA_SIZE as *const u32 as *mut _,
    },
    UserTaProperty {
        name: TA_PROP_STR_STACK_SIZE,
        prop_type: UserTaPropType::USER_TA_PROP_TYPE_U32,
        value: &TA_STACK_SIZE as *const u32 as *mut _,
    },
    UserTaProperty {
        name: TA_PROP_STR_VERSION,
        prop_type: UserTaPropType::USER_TA_PROP_TYPE_STRING,
        value: TA_VERSION as *const [u8] as *mut _,
    },
    UserTaProperty {
        name: TA_PROP_STR_DESCRIPTION,
        prop_type: UserTaPropType::USER_TA_PROP_TYPE_STRING,
        value: TA_DESCRIPTION as *const [u8] as *mut _,
    },
];
