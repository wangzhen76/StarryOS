// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.
//
// This file has been modified by KylinSoft on 2025.


use crate::syscalls::syscall_table::{_utee_cryp_obj_close, _utee_cryp_obj_get_attr, _utee_cryp_obj_get_info,
    _utee_cryp_obj_populate, _utee_cryp_obj_reset, _utee_cryp_obj_copy, _utee_storage_obj_del,_utee_cryp_obj_restrict_usage,
    _utee_storage_obj_create,_utee_storage_obj_open,_utee_cryp_obj_generate_key,_utee_cryp_obj_alloc, _utee_storage_alloc_enum, _utee_storage_free_enum, _utee_storage_reset_enum, _utee_storage_next_enum, _utee_storage_obj_read, _utee_storage_obj_write, _utee_storage_obj_trunc, _utee_storage_obj_seek};
use crate::tee_api_defines::*;
use crate::tee_api_types::{TEE_Attribute, TEE_ObjectInfo, TEE_ObjectHandle, TEE_Result, TEE_ObjectEnumHandle, TEE_Whence};
use crate::utee_types::utee_attribute;
use crate::api::tee_api_panic::TEE_Panic;
use crate::api::tee_api_mm::TEE_CheckMemoryAccessRights;



/// 默认使用标志
pub const TEE_USAGE_DEFAULT: u32 = 0xffffffff;

/// 将TEE属性转换为utee属性
pub unsafe fn __utee_from_attr(
    ua: *mut utee_attribute,
    attrs: *const TEE_Attribute,
    attr_count: u32,
) {
    unsafe {
        for n in 0..attr_count as usize {
            let ua_ptr = ua.add(n);
            let attr_ptr = attrs.add(n);

            (*ua_ptr).attribute_id = (*attr_ptr).attributeID;

            if (*attr_ptr).attributeID & TEE_ATTR_FLAG_VALUE != 0 {
                // 处理值类型属性
                (*ua_ptr).a = (*attr_ptr).content.value.a as u64;
                (*ua_ptr).b = (*attr_ptr).content.value.b as u64;
            } else {
                // 处理引用类型属性
                (*ua_ptr).a = (*attr_ptr).content.memref.buffer as u64;
                (*ua_ptr).b = (*attr_ptr).content.memref.size as u64;
            }
        }
    }
}


/// 获取对象信息（已弃用）
///
/// 注意：此函数已弃用，新代码应使用 [TEE_GetObjectInfo1] 函数
#[unsafe(no_mangle)]
pub extern "C" fn TEE_GetObjectInfo(object: TEE_ObjectHandle, object_info: &mut TEE_ObjectInfo) {
    let mut info = unsafe { std::mem::zeroed() };  // 使用 zeroed 替代 default
    let res = unsafe { _utee_cryp_obj_get_info(object as u64, &mut info) };

    if res != TEE_SUCCESS as usize {
        TEE_Panic(res as u32);
    }

    if info.obj_type == TEE_TYPE_CORRUPTED_OBJECT {
        // 对于损坏的对象，设置默认值
        object_info.objectSize = 0;
        object_info.maxObjectSize = 0;
        object_info.objectUsage = 0;
        object_info.dataSize = 0;
        object_info.dataPosition = 0;
        object_info.handleFlags = 0;
    } else {
        // 复制对象信息
        object_info.objectType = info.obj_type;
        object_info.objectSize = info.obj_size;
        object_info.maxObjectSize = info.max_obj_size;
        object_info.objectUsage = info.obj_usage;
        object_info.dataSize = info.data_size as usize;
        object_info.dataPosition = info.data_pos as usize;
        object_info.handleFlags = info.handle_flags;
    }
}

/// 获取对象信息
/// 
/// 此函数返回操作结果而不是 panic
#[unsafe(no_mangle)]
pub extern "C" fn TEE_GetObjectInfo1(object: TEE_ObjectHandle, object_info: &mut TEE_ObjectInfo) -> TEE_Result {
    let mut info = unsafe { std::mem::zeroed() };
    let res = unsafe { _utee_cryp_obj_get_info(object as u64, &mut info) } as TEE_Result;

    // 检查是否为非预期错误
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }

    // 总是复制对象信息，即使对象已损坏或存储不可用
    object_info.objectType = info.obj_type;
    object_info.objectSize = info.obj_size;
    object_info.maxObjectSize = info.max_obj_size;
    object_info.objectUsage = info.obj_usage;
    object_info.dataSize = info.data_size as usize;
    object_info.dataPosition = info.data_pos as usize;
    object_info.handleFlags = info.handle_flags;

    res
}

/// 限制对象使用（已弃用）
///
/// 注意：此函数已弃用，新代码应使用 [TEE_RestrictObjectUsage1] 函数
#[unsafe(no_mangle)]
pub extern "C" fn TEE_RestrictObjectUsage(object: TEE_ObjectHandle, object_usage: u32) {
    let mut info = unsafe { std::mem::zeroed() };
    unsafe { _utee_cryp_obj_get_info(object as u64, &mut info); }

    // 如果对象已损坏，则直接返回
    if info.obj_type == TEE_TYPE_CORRUPTED_OBJECT {
        return;
    }

    let res = TEE_RestrictObjectUsage1(object, object_usage);

    if res != TEE_SUCCESS {
        TEE_Panic(res as u32);
    }
}

/// 限制对象使用
///
/// 设置对象的使用限制，返回操作结果
#[unsafe(no_mangle)]
pub extern "C" fn TEE_RestrictObjectUsage1(object: TEE_ObjectHandle, object_usage: u32) -> TEE_Result {
    let res = unsafe {
        _utee_cryp_obj_restrict_usage(object as u64, object_usage as u64)
    } as TEE_Result;

    // 检查是否为非预期错误
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }

    res
}

/// 获取对象的缓冲区属性（已弃用）
///
/// 注意：此函数已弃用，新代码应使用 [TEE_GetObjectBufferAttribute1] 函数
#[unsafe(no_mangle)]
pub extern "C" fn TEE_GetObjectBufferAttribute(
    object: TEE_ObjectHandle,
    attribute_id: u32,
    buffer: *mut core::ffi::c_void,
    size: *mut usize,
) -> TEE_Result {

    // 检查参数有效性
    if cfg!(feature = "strict_annotation_checks") {
        let res = TEE_CheckMemoryAccessRights(
            TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE,
            size as *mut core::ffi::c_void,
            std::mem::size_of::<usize>(),
        );
        if res != 0 {
            eprintln!("[inout] size: error {:#010x}", res);
            TEE_Panic(0);
        }
    }

    let mut info = unsafe { std::mem::zeroed::<crate::utee_types::utee_object_info>() };
    let res = unsafe { _utee_cryp_obj_get_info(object as u64, &mut info) } as TEE_Result;

    if res != TEE_SUCCESS {
        return check_result_and_panic(res);
    }

    // 此函数仅支持引用类型属性
    if attribute_id & TEE_ATTR_FLAG_VALUE != 0 {
        return check_result_and_panic(TEE_ERROR_BAD_PARAMETERS);
    }

    let mut buffer_size: u64 = 0;
    unsafe {
        if !size.is_null() {
            buffer_size = *size as u64;
        }
    }

    let res = unsafe {
        _utee_cryp_obj_get_attr(
            object as u64,
            attribute_id as u64,
            buffer,
            &mut buffer_size,
        )
    } as TEE_Result;

    unsafe {
        if !size.is_null() {
            *size = buffer_size as usize;
        }
    }

    check_result_and_panic(res)
}

/// 获取对象的缓冲区属性
///
/// 返回对象的缓冲区属性，将数据写入提供的缓冲区
#[unsafe(no_mangle)]
pub extern "C" fn TEE_GetObjectBufferAttribute1(
    object: TEE_ObjectHandle,
    attribute_id: u32,
    buffer: *mut core::ffi::c_void,
    size: *mut usize,
) -> TEE_Result {
    // 检查参数有效性
    if size.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    let mut info = unsafe { std::mem::zeroed::<crate::utee_types::utee_object_info>() };
    let res = unsafe { _utee_cryp_obj_get_info(object as u64, &mut info) } as TEE_Result;

    if res != TEE_SUCCESS {
        return check_result_and_panic(res);
    }

    // 此函数仅支持引用类型属性
    if attribute_id & TEE_ATTR_FLAG_VALUE != 0 {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 首先获取所需缓冲区大小
    let mut required_size: u64 = 0;
    let res = unsafe { _utee_cryp_obj_get_attr(
        object as u64,
        attribute_id as u64,
        core::ptr::null_mut(),
        &mut required_size,
    ) as TEE_Result
    };

    if res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER {
        unsafe {
            *size = required_size as usize;
        }
    } else {
        return check_result_and_panic(res);
    }

    // 如果提供了缓冲区且大小足够，获取实际数据
    if !buffer.is_null() && unsafe { *size } >= required_size as usize {
        let res = unsafe { _utee_cryp_obj_get_attr(
            object as u64,
            attribute_id as u64,
            buffer,
            &mut required_size,
        ) as TEE_Result
        };

        if res != TEE_SUCCESS {
            return check_result_and_panic(res);
        }

        unsafe {
            *size = required_size as usize;
        }
    }

    TEE_SUCCESS
}

/// 检查结果并对非预期错误进行 panic
fn check_result_and_panic(res: TEE_Result) -> TEE_Result {
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_ITEM_NOT_FOUND &&
       res != TEE_ERROR_SHORT_BUFFER &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }
    res
}

/// 处理结果并返回
fn handle_result_and_return(res: TEE_Result, a: *mut u32, b: *mut u32, value_a: u32, value_b: u32) -> TEE_Result {
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_ITEM_NOT_FOUND &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res);
    }

    if res == TEE_SUCCESS {
        if !a.is_null() {
            unsafe { *a = value_a };
        }
        if !b.is_null() {
            unsafe { *b = value_b };
        }
    }

    res
}

/// 获取对象值属性
///
/// 此函数仅支持值类型属性（由TEE_ATTR_FLAG_VALUE标识）
#[unsafe(no_mangle)]
pub extern "C" fn TEE_GetObjectValueAttribute(
    object: TEE_ObjectHandle,
    attribute_id: u32,
    a: *mut u32,
    b: *mut u32,
) -> TEE_Result {

    // 检查输出参数的有效性（如果非空）
    if cfg!(feature = "strict_annotation_checks") {
        if !a.is_null() {
            let res = TEE_CheckMemoryAccessRights(
                TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE,
                a as *mut core::ffi::c_void,
                std::mem::size_of::<u32>(),
            );
            if res != 0 {
                eprintln!("[inout] a: error {:#010x}", res);
                TEE_Panic(0);
            }
        }
        if !b.is_null() {
            let res = TEE_CheckMemoryAccessRights(
                TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE,
                b as *mut core::ffi::c_void,
                std::mem::size_of::<u32>(),
            );
            if res != 0 {
                eprintln!("[inout] b: error {:#010x}", res);
                TEE_Panic(0);
            }
        }
    }

    let mut info = unsafe { std::mem::zeroed::<crate::utee_types::utee_object_info>() };
    let res = unsafe { _utee_cryp_obj_get_info(object as u64, &mut info) } as TEE_Result;

    if res != TEE_SUCCESS {
        return handle_result_and_return(res, a, b, 0, 0);
    }

    // 此函数仅支持值类型属性
    if attribute_id & TEE_ATTR_FLAG_VALUE == 0 {
        let res = TEE_ERROR_BAD_PARAMETERS;
        return handle_result_and_return(res, a, b, 0, 0);
    }

    // 创建缓冲区来存储属性值
    let mut buf = [0u32; 2];
    let mut size = std::mem::size_of_val(&buf) as u64;

    let res = unsafe { _utee_cryp_obj_get_attr(
        object as u64,
        attribute_id as u64,
        buf.as_mut_ptr() as *mut core::ffi::c_void,
        &mut size,
    ) as TEE_Result
    };

    // 检查返回结果是否为非预期错误
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_ITEM_NOT_FOUND &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res);
    }

    // 验证返回的大小是否正确
    if size != std::mem::size_of_val(&buf) as u64 {
        TEE_Panic(0);
    }

    // 如果成功，将值写入输出参数
    if res == TEE_SUCCESS {
        if !a.is_null() {
            unsafe { *a = buf[0] };
        }
        if !b.is_null() {
            unsafe { *b = buf[1] };
        }
    }

    res
}

/// 关闭对象
///
/// 关闭并释放指定的TEE对象句柄
#[unsafe(no_mangle)]
pub extern "C" fn TEE_CloseObject(object: TEE_ObjectHandle) {
    // 检查是否为NULL句柄
    if object.is_null() {
        return;
    }

    let res = unsafe { _utee_cryp_obj_close(object as u64) } as TEE_Result;

    // 检查返回结果，如果不是成功则panic
    if res != TEE_SUCCESS {
        TEE_Panic(res as u32);
    }
}

/// 分配临时对象
/// 
/// 分配一个新的临时对象句柄
#[unsafe(no_mangle)]
pub extern "C" fn TEE_AllocateTransientObject(
    object_type: u32, // TEE_ObjectType
    max_object_size: u32,
    object: *mut TEE_ObjectHandle,
) -> TEE_Result {
    // 数据类型对象不支持
    if object_type == TEE_TYPE_DATA {
        return TEE_ERROR_NOT_SUPPORTED;
    }

    __GP11_TEE_AllocateTransientObject(object_type, max_object_size, object)
}

/// GP11标准的分配临时对象实现
///
/// 内部函数，用于实际分配临时对象
#[unsafe(no_mangle)]
pub extern "C" fn __GP11_TEE_AllocateTransientObject(
    object_type: u32, // TEE_ObjectType
    max_key_size: u32,
    object: *mut TEE_ObjectHandle,
) -> TEE_Result {

    // 检查输出参数的有效性
    if cfg!(feature = "strict_annotation_checks") {
        let res = TEE_CheckMemoryAccessRights(
            TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE,
            object as *mut core::ffi::c_void,
            std::mem::size_of::<TEE_ObjectHandle>(),
        );
        if res != 0 {
            eprintln!("[inout] object: error {:#010x}", res);
            TEE_Panic(0);
        }
    }

    let mut obj: u32 = 0;

    let res = unsafe {
        _utee_cryp_obj_alloc(
            object_type as u64,
            max_key_size as u64,
            &mut obj,
        )
    } as TEE_Result;

    // 检查返回结果是否为非预期错误
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_OUT_OF_MEMORY &&
       res != TEE_ERROR_NOT_SUPPORTED {
        TEE_Panic(res as u32);
    }

    // 如果成功，将对象句柄写入输出参数
    if res == TEE_SUCCESS {
        unsafe {
            *object = obj as TEE_ObjectHandle;
        }
    }

    res
}

/// 释放临时对象
/// 
/// 释放指定的临时对象句柄，仅当对象不是持久化对象时
#[unsafe(no_mangle)]
pub extern "C" fn TEE_FreeTransientObject(object: TEE_ObjectHandle) {
    // 检查是否为NULL句柄
    if object.is_null() {
        return;
    }

    let mut info = unsafe { std::mem::zeroed::<crate::utee_types::utee_object_info>() };
    let res = unsafe { _utee_cryp_obj_get_info(object as u64, &mut info) } as TEE_Result;

    if res != TEE_SUCCESS {
        TEE_Panic(res as u32);
    }

    // 检查对象是否为持久化对象，如果是则panic
    if (info.handle_flags & TEE_HANDLE_FLAG_PERSISTENT) != 0 {
        TEE_Panic(0);
    }

    let res = unsafe { _utee_cryp_obj_close(object as u64) } as TEE_Result;

    if res != TEE_SUCCESS {
        TEE_Panic(res as u32);
    }
}

/// 重置临时对象
/// 
/// 重置指定的临时对象，仅当对象不是持久化对象时
#[unsafe(no_mangle)]
pub extern "C" fn TEE_ResetTransientObject(object: TEE_ObjectHandle) {
    // 检查是否为NULL句柄
    if object.is_null() {
        return;
    }

    let mut info = unsafe { std::mem::zeroed::<crate::utee_types::utee_object_info>() };
    let res = unsafe { _utee_cryp_obj_get_info(object as u64, &mut info) } as TEE_Result;

    if res != TEE_SUCCESS {
        TEE_Panic(res as u32);
    }

    // 检查对象是否为持久化对象，如果是则panic
    if (info.handle_flags & TEE_HANDLE_FLAG_PERSISTENT) != 0 {
        TEE_Panic(0);
    }

    let res = unsafe { _utee_cryp_obj_reset(object as u64) } as TEE_Result;

    if res != TEE_SUCCESS {
        TEE_Panic(res as u32);
    }
}

/// 填充临时对象
///
/// 使用指定的属性填充临时对象
#[unsafe(no_mangle)]
pub extern "C" fn TEE_PopulateTransientObject(
    object: TEE_ObjectHandle,
    attrs: *const TEE_Attribute,
    attr_count: u32,
) -> TEE_Result {
    // 检查属性数组的有效性
    // 注意：这里简化处理，不进行详细的属性检查

    let mut info = unsafe { std::mem::zeroed::<crate::utee_types::utee_object_info>() };
    let res = unsafe { _utee_cryp_obj_get_info(object as u64, &mut info) } as TEE_Result;

    if res != TEE_SUCCESS {
        TEE_Panic(res as u32);
    }

    // 必须是临时对象（不能是持久化对象）
    if (info.handle_flags & TEE_HANDLE_FLAG_PERSISTENT) != 0 {
        TEE_Panic(0);
    }

    // 对象不能已经被初始化
    if (info.handle_flags & TEE_HANDLE_FLAG_INITIALIZED) != 0 {
        TEE_Panic(0);
    }

    // 创建临时属性数组并转换属性
    let mut ua = vec![utee_attribute::default(); attr_count as usize];

    unsafe {
        __utee_from_attr(ua.as_mut_ptr(), attrs, attr_count);
    }

    let res = unsafe { _utee_cryp_obj_populate(
        object as u64,
        ua.as_mut_ptr(),
        attr_count as u64,
    ) as TEE_Result
    };

    if res != TEE_SUCCESS && res != TEE_ERROR_BAD_PARAMETERS {
        TEE_Panic(res as u32);
    }

    res
}

/// 初始化引用属性
/// 
/// 初始化一个引用类型的TEE属性
#[unsafe(no_mangle)]
pub extern "C" fn TEE_InitRefAttribute(
    attr: *mut TEE_Attribute,
    attribute_id: u32,
    buffer: *const core::ffi::c_void,
    length: usize,
) {
    // 检查输出参数的有效性
    if cfg!(feature = "strict_annotation_checks") {
        let res = TEE_CheckMemoryAccessRights(
            TEE_MEMORY_ACCESS_WRITE,
            attr as *mut core::ffi::c_void,
            std::mem::size_of::<TEE_Attribute>(),
        );
        if res != 0 {
            eprintln!("[out] attr: error {:#010x}", res);
            TEE_Panic(0);
        }
    }

    // 检查属性ID是否为引用类型（不能是值类型）
    if (attribute_id & TEE_ATTR_FLAG_VALUE) != 0 {
        TEE_Panic(0);
    }

    // 初始化属性
    unsafe {
        if !attr.is_null() {
            (*attr).attributeID = attribute_id;
            (*attr).content.memref.buffer = buffer as *mut core::ffi::c_void;
            (*attr).content.memref.size = length;
        }
    }
}

/// 初始化值属性
/// 
/// 初始化一个值类型的TEE属性
#[unsafe(no_mangle)]
pub extern "C" fn TEE_InitValueAttribute(
    attr: *mut TEE_Attribute,
    attribute_id: u32,
    a: u32,
    b: u32,
) {
    // 检查输出参数的有效性
    if cfg!(feature = "strict_annotation_checks") {
        let res = TEE_CheckMemoryAccessRights(
            TEE_MEMORY_ACCESS_WRITE,
            attr as *mut core::ffi::c_void,
            std::mem::size_of::<TEE_Attribute>(),
        );
        if res != 0 {
            eprintln!("[out] attr: error {:#010x}", res);
            TEE_Panic(0);
        }
    }

    // 检查属性ID是否为值类型（必须是值类型）
    if (attribute_id & TEE_ATTR_FLAG_VALUE) == 0 {
        TEE_Panic(0);
    }

    // 初始化属性
    unsafe {
        if !attr.is_null() {
            (*attr).attributeID = attribute_id;
            (*attr).content.value.a = a;
            (*attr).content.value.b = b;
        }
    }
}

/// 复制对象属性（已弃用）
/// 
/// 注意：此函数已弃用，新代码应使用 [TEE_CopyObjectAttributes1] 函数
#[unsafe(no_mangle)]
pub extern "C" fn TEE_CopyObjectAttributes(
    dest_object: TEE_ObjectHandle,
    src_object: TEE_ObjectHandle,
) {
    let mut src_info = unsafe { std::mem::zeroed::<crate::utee_types::utee_object_info>() };
    let _res = unsafe {
        _utee_cryp_obj_get_info(src_object as u64, &mut src_info)
    } as TEE_Result;

    // 如果源对象已损坏，则直接返回
    if src_info.obj_type == TEE_TYPE_CORRUPTED_OBJECT {
        return;
    }

    let res = TEE_CopyObjectAttributes1(dest_object, src_object);

    if res != TEE_SUCCESS {
        TEE_Panic(res as u32);
    }
}

/// 复制对象属性
/// 
/// 将源对象的属性复制到目标对象
#[unsafe(no_mangle)]
pub extern "C" fn TEE_CopyObjectAttributes1(
    dest_object: TEE_ObjectHandle,
    src_object: TEE_ObjectHandle,
) -> TEE_Result {
    let mut dst_info = unsafe { std::mem::zeroed::<crate::utee_types::utee_object_info>() };
    let mut src_info = unsafe { std::mem::zeroed::<crate::utee_types::utee_object_info>() };
    
    // 获取目标对象信息
    let mut res = unsafe { 
        _utee_cryp_obj_get_info(dest_object as u64, &mut dst_info) 
    } as TEE_Result;
    
    if res != TEE_SUCCESS {
        return check_copy_object_attributes_result(res);
    }

    // 获取源对象信息
    res = unsafe { 
        _utee_cryp_obj_get_info(src_object as u64, &mut src_info) 
    } as TEE_Result;
    
    if res != TEE_SUCCESS {
        return check_copy_object_attributes_result(res);
    }

    // 源对象必须已初始化
    if (src_info.handle_flags & TEE_HANDLE_FLAG_INITIALIZED) == 0 {
        TEE_Panic(0);
    }

    // 目标对象不能是持久化对象
    if (dst_info.handle_flags & TEE_HANDLE_FLAG_PERSISTENT) != 0 {
        TEE_Panic(0);
    }

    // 目标对象不能已经被初始化
    if (dst_info.handle_flags & TEE_HANDLE_FLAG_INITIALIZED) != 0 {
        TEE_Panic(0);
    }

    // 执行对象属性复制
    res = unsafe {_utee_cryp_obj_copy(dest_object as u64, src_object as u64)} as TEE_Result;

    check_copy_object_attributes_result(res)
}

/// 检查复制对象属性的结果
fn check_copy_object_attributes_result(res: TEE_Result) -> TEE_Result {
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }

    res
}

/// 生成密钥
/// 
/// 为指定对象生成密钥
#[unsafe(no_mangle)]
pub extern "C" fn TEE_GenerateKey(
    object: TEE_ObjectHandle,
    key_size: u32,
    params: *const TEE_Attribute,
    param_count: u32,
) -> TEE_Result {
    // 检查属性参数的有效性
    if cfg!(feature = "strict_annotation_checks") && param_count > 0 {
        let res = TEE_CheckMemoryAccessRights(
            TEE_MEMORY_ACCESS_READ,
            params as *mut core::ffi::c_void,
            std::mem::size_of::<TEE_Attribute>() * param_count as usize,
        );
        if res != 0 {
            eprintln!("[in] attrs: error {:#010x}", res);
            TEE_Panic(0);
        }
    }

    // 创建临时属性数组并转换属性
    let mut ua = vec![utee_attribute::default(); param_count as usize];

    unsafe {
        __utee_from_attr(ua.as_mut_ptr(), params, param_count);
    }

    let res = unsafe {
        _utee_cryp_obj_generate_key(
            object as u64,
            key_size as u64,
            ua.as_ptr(),
            param_count as u64,
        )
    } as TEE_Result;

    if res != TEE_SUCCESS && res != TEE_ERROR_BAD_PARAMETERS {
        TEE_Panic(res as u32);
    }

    res
}

/// 打开持久化对象
/// 
/// 打开一个持久化存储对象
#[unsafe(no_mangle)]
pub extern "C" fn TEE_OpenPersistentObject(
    storage_id: u32,
    object_id: *const core::ffi::c_void,
    object_id_len: usize,
    flags: u32,
    object: *mut TEE_ObjectHandle,
) -> TEE_Result {
    // 检查输出参数的有效性
    if cfg!(feature = "strict_annotation_checks") {
        let res = TEE_CheckMemoryAccessRights(
            TEE_MEMORY_ACCESS_WRITE,
            object as *mut core::ffi::c_void,
            std::mem::size_of::<TEE_ObjectHandle>(),
        );
        if res != 0 {
            eprintln!("[out] object: error {:#010x}", res);
            TEE_Panic(0);
        }
    }

    let mut obj: u32 = 0;

    let res = unsafe {
        _utee_storage_obj_open(
            storage_id as u64,
            object_id,
            object_id_len,
            flags as u64,
            &mut obj,
        )
    } as TEE_Result;

    // 如果成功，将对象句柄写入输出参数
    if res == TEE_SUCCESS {
        unsafe {
            *object = obj as TEE_ObjectHandle;
        }
    } else {
        // 如果失败，将对象句柄设置为NULL
        unsafe {
            *object = core::ptr::null_mut();
        }
    }

    // 检查返回结果是否为非预期错误
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_ITEM_NOT_FOUND &&
       res != TEE_ERROR_ACCESS_CONFLICT &&
       res != TEE_ERROR_OUT_OF_MEMORY &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }

    res
}

/// 创建持久化对象
/// 
/// 创建一个持久化存储对象
#[unsafe(no_mangle)]
pub extern "C" fn TEE_CreatePersistentObject(
    storage_id: u32,
    object_id: *const core::ffi::c_void,
    object_id_len: usize,
    flags: u32,
    attributes: TEE_ObjectHandle,
    initial_data: *const core::ffi::c_void,
    initial_data_len: usize,
    object: *mut TEE_ObjectHandle,
) -> TEE_Result {
    let mut obj: u32 = 0;
    let obj_ptr: *mut u32;

    // 检查输出参数的有效性
    if !object.is_null() {
        if cfg!(feature = "strict_annotation_checks") {
            let res = TEE_CheckMemoryAccessRights(
                TEE_MEMORY_ACCESS_WRITE,
                object as *mut core::ffi::c_void,
                std::mem::size_of::<TEE_ObjectHandle>(),
            );
            if res != 0 {
                eprintln!("[out] object: error {:#010x}", res);
                TEE_Panic(0);
            }
        }
        obj_ptr = &mut obj;
    } else {
        obj_ptr = core::ptr::null_mut();
    }

    let res = unsafe {
        _utee_storage_obj_create(
            storage_id as u64,
            object_id,
            object_id_len,
            flags as u64,
            attributes as u64,
            initial_data,
            initial_data_len,
            obj_ptr,
        )
    } as TEE_Result;

    // 如果成功且输出参数不为空，将对象句柄写入输出参数
    if res == TEE_SUCCESS && !object.is_null() {
        unsafe {
            *object = obj as TEE_ObjectHandle;
        }
    } else if res != TEE_SUCCESS && !object.is_null() {
        // 如果失败且输出参数不为空，将对象句柄设置为NULL
        unsafe {
            *object = core::ptr::null_mut();
        }
    }

    // 检查返回结果是否为非预期错误
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_ITEM_NOT_FOUND &&
       res != TEE_ERROR_ACCESS_CONFLICT &&
       res != TEE_ERROR_OUT_OF_MEMORY &&
       res != TEE_ERROR_STORAGE_NO_SPACE &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }

    res
}

/// 关闭并删除持久化对象（已弃用）
/// 
/// 注意：此函数已弃用，新代码应使用 [TEE_CloseAndDeletePersistentObject1] 函数
#[unsafe(no_mangle)]
pub extern "C" fn TEE_CloseAndDeletePersistentObject(object: TEE_ObjectHandle) {
    // 检查是否为NULL句柄
    if object.is_null() {
        return;
    }

    let res = TEE_CloseAndDeletePersistentObject1(object);

    if res != TEE_SUCCESS {
        TEE_Panic(0);
    }
}

/// 关闭并删除持久化对象
/// 
/// 关闭并删除指定的持久化对象
#[unsafe(no_mangle)]
pub extern "C" fn TEE_CloseAndDeletePersistentObject1(object: TEE_ObjectHandle) -> TEE_Result {
    // 检查是否为NULL句柄
    if object.is_null() {
        return TEE_SUCCESS;
    }

    let res = unsafe {_utee_storage_obj_del(object as u64)} as TEE_Result;

    // 检查返回结果是否为非预期错误
    if res != TEE_SUCCESS && res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }

    res
}

/// 重命名持久化对象
/// 
/// 将指定的持久化对象重命名
#[unsafe(no_mangle)]
pub extern "C" fn TEE_RenamePersistentObject(
    object: TEE_ObjectHandle,
    new_object_id: *const core::ffi::c_void,
    new_object_id_len: usize,
) -> TEE_Result {
    // 检查对象句柄是否为空
    let res = if object.is_null() {
        TEE_ERROR_ITEM_NOT_FOUND
    } else {
        // 调用底层系统调用进行重命名
        // unsafe {
        //     _utee_storage_obj_rename(object as u64, new_object_id, new_object_id_len) as TEE_Result
        // }
        TEE_ERROR_ITEM_NOT_FOUND
    };

    // 检查返回结果，如果不是预期的错误类型则panic
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_ACCESS_CONFLICT &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }

    res
}

/// 分配持久化对象枚举器
/// 
/// 分配一个新的持久化对象枚举器句柄
#[unsafe(no_mangle)]
pub extern "C" fn TEE_AllocatePersistentObjectEnumerator(
    object_enumerator: *mut TEE_ObjectEnumHandle,
) -> TEE_Result {
    // 检查输出参数的有效性
    if cfg!(feature = "strict_annotation_checks") {
        let res = TEE_CheckMemoryAccessRights(
            TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE,
            object_enumerator as *mut core::ffi::c_void,
            std::mem::size_of::<TEE_ObjectEnumHandle>(),
        );
        if res != 0 {
            eprintln!("[out] objectEnumerator: error {:#010x}", res);
            TEE_Panic(0);
        }
    }

    let mut oe: u32 = 0;

    let res = unsafe {
        _utee_storage_alloc_enum(&mut oe)
    } as TEE_Result;

    // 如果失败，将枚举器句柄设置为NULL
    if res != TEE_SUCCESS {
        oe = TEE_HANDLE_NULL as u32;
    }

    // 将枚举器句柄写入输出参数
    unsafe {
        *object_enumerator = oe as TEE_ObjectEnumHandle;
    }

    // 检查返回结果，如果不是预期的错误类型则panic
    if res != TEE_SUCCESS && res != TEE_ERROR_ACCESS_CONFLICT {
        TEE_Panic(res as u32);
    }

    res
}


/// 释放持久化对象枚举器
/// 
/// 释放指定的持久化对象枚举器句柄
#[unsafe(no_mangle)]
pub extern "C" fn TEE_FreePersistentObjectEnumerator(
    object_enumerator: TEE_ObjectEnumHandle,
) {
    // 检查枚举器句柄是否为空
    if object_enumerator.is_null() {
        return;
    }

    let res = unsafe {
        _utee_storage_free_enum(object_enumerator as u64)
    } as TEE_Result;

    // 检查返回结果，如果不是成功则panic
    if res != TEE_SUCCESS {
        TEE_Panic(res as u32);
    }
}

/// 重置持久化对象枚举器
/// 
/// 重置指定的持久化对象枚举器句柄
#[unsafe(no_mangle)]
pub extern "C" fn TEE_ResetPersistentObjectEnumerator(
    object_enumerator: TEE_ObjectEnumHandle,
) {
    // 检查枚举器句柄是否为空
    if object_enumerator.is_null() {
        return;
    }

    let res = unsafe {
        _utee_storage_reset_enum(object_enumerator as u64)
    } as TEE_Result;

    // 检查返回结果，如果不是成功则panic
    if res != TEE_SUCCESS {
        TEE_Panic(res as u32);
    }
}

/// 获取下一个持久化对象
/// 
/// 从枚举器中获取下一个持久化对象的信息和ID
#[unsafe(no_mangle)]
pub extern "C" fn TEE_GetNextPersistentObject(
    object_enumerator: TEE_ObjectEnumHandle,
    object_info: *mut TEE_ObjectInfo,
    object_id: *mut core::ffi::c_void,
    object_id_len: *mut usize,
) -> TEE_Result {
    // 检查参数有效性
    if cfg!(feature = "strict_annotation_checks") {
        // 检查 object_info 参数（如果非空）
        if !object_info.is_null() {
            let res = TEE_CheckMemoryAccessRights(
                TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE,
                object_info as *mut core::ffi::c_void,
                std::mem::size_of::<TEE_ObjectInfo>(),
            );
            if res != 0 {
                eprintln!("[out] objectInfo: error {:#010x}", res);
                TEE_Panic(0);
            }
        }
        
        // 检查 object_id_len 参数
        let res = TEE_CheckMemoryAccessRights(
            TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE,
            object_id_len as *mut core::ffi::c_void,
            std::mem::size_of::<usize>(),
        );
        if res != 0 {
            eprintln!("[out] objectIDLen: error {:#010x}", res);
            TEE_Panic(0);
        }
    }

    // 检查必要参数是否为空
    if object_id.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    let mut info = unsafe { std::mem::zeroed::<crate::utee_types::utee_object_info>() };
    let mut len: u64 = 0;

    unsafe {
        if !object_id_len.is_null() {
            len = *object_id_len as u64;
        }
    }

    let res = unsafe {
        _utee_storage_next_enum(
            object_enumerator as u64,
            &mut info,
            object_id,
            &mut len,
        )
    } as TEE_Result;

    // 如果提供了object_info参数，复制对象信息
    if !object_info.is_null() {
        unsafe {
            (*object_info).objectType = info.obj_type;
            (*object_info).objectSize = info.obj_size;
            (*object_info).maxObjectSize = info.max_obj_size;
            (*object_info).objectUsage = info.obj_usage;
            (*object_info).dataSize = info.data_size as usize;
            (*object_info).dataPosition = info.data_pos as usize;
            (*object_info).handleFlags = info.handle_flags;
        }
    }

    // 更新objectIDLen
    unsafe {
        if !object_id_len.is_null() {
            *object_id_len = len as usize;
        }
    }

    // 检查返回结果，如果不是预期的错误类型则panic
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_ITEM_NOT_FOUND &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }

    res
}

/// 读取对象数据
/// 
/// 从持久化对象中读取数据
#[unsafe(no_mangle)]
pub extern "C" fn TEE_ReadObjectData(
    object: TEE_ObjectHandle,
    buffer: *mut core::ffi::c_void,
    size: usize,
    count: *mut usize,
) -> TEE_Result {
    // 检查对象句柄是否为空
    if object.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 检查参数有效性
    if cfg!(feature = "strict_annotation_checks") {
        let res = TEE_CheckMemoryAccessRights(
            TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE,
            count as *mut core::ffi::c_void,
            std::mem::size_of::<usize>(),
        );
        if res != 0 {
            eprintln!("[out] count: error {:#010x}", res);
            TEE_Panic(0);
        }
    }

    let mut cnt64: u64 = 0;
    unsafe {
        if !count.is_null() {
            cnt64 = *count as u64;
        }
    }

    let res = unsafe {
        _utee_storage_obj_read(
            object as u64,
            buffer,
            size,
            &mut cnt64,
        )
    } as TEE_Result;

    // 更新count值
    unsafe {
        if !count.is_null() {
            *count = cnt64 as usize;
        }
    }

    // 检查返回结果，如果不是预期的错误类型则panic
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }

    res
}

/// 写入对象数据
/// 
/// 向持久化对象写入数据
#[unsafe(no_mangle)]
pub extern "C" fn TEE_WriteObjectData(
    object: TEE_ObjectHandle,
    buffer: *const core::ffi::c_void,
    size: usize,
) -> TEE_Result {
    // 检查对象句柄是否为空
    if object.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 检查数据大小是否超过最大限制
    if size > TEE_DATA_MAX_POSITION as usize {
        return TEE_ERROR_OVERFLOW;
    }

    // 检查参数有效性
    if cfg!(feature = "strict_annotation_checks") && size > 0 && !buffer.is_null() {
        let res = TEE_CheckMemoryAccessRights(
            TEE_MEMORY_ACCESS_READ,
            buffer as *mut core::ffi::c_void,
            size,
        );
        if res != 0 {
            eprintln!("[in] buffer: error {:#010x}", res);
            TEE_Panic(0);
        }
    }

    let res = unsafe {
        _utee_storage_obj_write(
            object as u64,
            buffer,
            size,
        )
    } as TEE_Result;

    // 检查返回结果，如果不是预期的错误类型则panic
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_STORAGE_NO_SPACE &&
       res != TEE_ERROR_OVERFLOW &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }

    res
}

/// 截断对象数据
/// 
/// 截断持久化对象的数据到指定大小
#[unsafe(no_mangle)]
pub extern "C" fn TEE_TruncateObjectData(
    object: TEE_ObjectHandle,
    size: usize,
) -> TEE_Result {
    // 检查对象句柄是否为空
    if object.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    let res = unsafe {
        _utee_storage_obj_trunc(
            object as u64,
            size,  // 直接使用 usize，不需要转换为 u64
        )
    } as TEE_Result;

    // 检查返回结果，如果不是预期的错误类型则panic
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_STORAGE_NO_SPACE &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }

    res
}


/// 寻找对象数据
/// 
/// 设置持久化对象的数据访问位置
/// 寻找对象数据
/// 
/// 设置持久化对象的数据访问位置
#[unsafe(no_mangle)]
pub extern "C" fn TEE_SeekObjectData(
    object: TEE_ObjectHandle,
    offset: i64,  // intmax_t 对应 i64
    whence: TEE_Whence,
) -> TEE_Result {
    // 检查对象句柄是否为空
    if object.is_null() {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 获取对象信息
    let mut info = unsafe { std::mem::zeroed::<crate::utee_types::utee_object_info>() };
    let mut res = unsafe {
        _utee_cryp_obj_get_info(object as u64, &mut info) as TEE_Result
    };

    if res != TEE_SUCCESS {
        return res;
    }

    // 保存whence的转换值，避免移动错误
    let whence_u32 = whence as u32;
    let whence_u64 = whence as u64;

    // 检查偏移量和寻址方式
    match whence_u32 {
        TEE_DATA_SEEK_SET => {
            if offset > 0 && offset as u32 > TEE_DATA_MAX_POSITION {
                return TEE_ERROR_OVERFLOW;
            }
        },
        TEE_DATA_SEEK_CUR => {
            if offset > 0 && (
                offset as u32 + info.data_pos > TEE_DATA_MAX_POSITION as u32 ||
                offset as u32 + info.data_pos < info.data_pos
            ) {
                return TEE_ERROR_OVERFLOW;
            }
        },
        TEE_DATA_SEEK_END => {
            if offset > 0 && (
                offset as u32 + info.data_size > TEE_DATA_MAX_POSITION as u32 ||
                offset as u32 + info.data_size < info.data_size
            ) {
                return TEE_ERROR_OVERFLOW;
            }
        },
        _ => {
            return TEE_ERROR_ITEM_NOT_FOUND;
        }
    }

    // 执行寻址操作
    res = unsafe {
        _utee_storage_obj_seek(object as u64, offset as i32, whence_u64) as TEE_Result
    };

    // 检查返回结果，如果不是预期的错误类型则panic
    if res != TEE_SUCCESS &&
       res != TEE_ERROR_OVERFLOW &&
       res != TEE_ERROR_CORRUPT_OBJECT &&
       res != TEE_ERROR_STORAGE_NOT_AVAILABLE {
        TEE_Panic(res as u32);
    }

    res
}