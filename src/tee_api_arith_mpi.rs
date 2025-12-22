// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.
//
// This file has been modified by KylinSoft on 2025.

// TEE Internal Core API Specification – Public Release v1.3.1
// 8 TEE Arithmetical API

use std::ops::ShrAssign;
use mbedtls::bignum::Mpi;
use mbedtls::rng::RngCallback;
use mbedtls::error::Error;
pub use mbedtls_sys_auto::mpi_sint;

// 为了访问底层函数，我们需要导入正确的模块
use mbedtls_sys_auto as mbedtls_sys;

/// TEE BigInt 扩展 trait
pub trait TeeBigIntExt {
    /// 将 MPI 转换为 TEE_BigInt
    unsafe fn to_teebigint(&self, bigint: *mut TEE_BigInt, alloc_size: usize) -> Result<(), Error>;
    
    /// 从 TEE_BigInt 创建 MPI
    unsafe fn from_teebigint(bigint: *const TEE_BigInt) -> Result<Self, Error>
    where
        Self: Sized;
}

/// 为 Mpi 实现 TEE BigInt 扩展 trait
impl TeeBigIntExt for Mpi {
    /// 将 Mpi 对象复制到 TEE_BigInt 结构中
    /// 
    /// 注意：mbedtls 使用 64-bit limbs，而 TEE_BigInt 使用 32-bit limbs
    unsafe fn to_teebigint(&self, bigint: *mut TEE_BigInt, alloc_size: usize) -> Result<(), Error> {
        unsafe {
            if bigint.is_null() {
                return Err(mbedtls::error::codes::MpiBadInputData.into());
            }

        // 计算 MPI 中有效 limbs 的数量（去除尾部的零值）
        let mpi_limbs_count = {
            let handle: *const mbedtls_sys::mpi = self.into();
            let mut limbs_count = (*handle).n;

            // 去除尾部的零值 limbs
            while limbs_count > 0 && self.get_limb(limbs_count - 1) == 0 {
                limbs_count -= 1;
            }
            limbs_count
        };

        // 计算 TEE_BigInt 需要的 32-bit limbs 数量
        // 每个 64-bit limb 都需要 2 个 32-bit limbs
        let mut tee_limbs_count = 0;
        for i in 0..mpi_limbs_count {
            let limb = self.get_limb(i);
            if i == mpi_limbs_count - 1 {
                // 最高位的 limb
                if limb == 0 {
                    continue; // 跳过零 limb
                } else if limb <= 0xFFFFFFFF {
                    // 如果高32位是0，只需要1个32-bit limb
                    tee_limbs_count += 1;
                } else {
                    // 需要2个32-bit limbs
                    tee_limbs_count += 2;
                }
            } else {
                // 非最高位的 limb，总是需要 2 个 32-bit limbs
                tee_limbs_count += 2;
            }
        }

        // 检查目标缓冲区是否足够大
        if alloc_size < tee_limbs_count {
            return Err(mbedtls::error::codes::MpiBufferTooSmall.into());
        }

        // 将指针转换为头部结构
        let header = bigint as *mut BigintHdr;

        // 设置头部信息
        let handle: *const mbedtls_sys::mpi = self.into();
        (*header).sign = (*handle).s;                    // 符号位
        (*header).alloc_size = alloc_size as u16;         // 分配大小
        (*header).nblimbs = tee_limbs_count as u16;      // limbs 数量


        // 复制数据，将 64-bit limbs 转换为 32-bit limbs
        let mut tee_index = 0;
        for i in 0..mpi_limbs_count {
            let limb = self.get_limb(i);
            
            // 存储低 32 位
            let low_ptr = bigint.add(2 + tee_index) as *mut u32;
            *low_ptr = (limb & 0xFFFFFFFF) as u32;
            tee_index += 1;
            
            // 如果需要，存储高 32 位
            if i < mpi_limbs_count - 1 || limb > 0xFFFFFFFF {
                let high_ptr = bigint.add(2 + tee_index) as *mut u32;
                *high_ptr = ((limb >> 32) & 0xFFFFFFFF) as u32;
                tee_index += 1;
            }
        }

        Ok(())
        }
    }
    
    /// 从 TEE_BigInt 结构体创建 Mpi 对象
    /// 
    /// 从 TEE_BigInt 提取数据并初始化 Mpi
    unsafe fn from_teebigint(bigint: *const TEE_BigInt) -> Result<Self, Error> {
        unsafe {
            if bigint.is_null() {
                // 如果输入为空，返回0
                return Mpi::new(0);
            }

            // 将指针转换为头部结构
            let header = bigint as *const BigintHdr;
            let sign = (*header).sign;           // 符号位
            let nblimbs = (*header).nblimbs as usize;  // limbs 数量

            // 检查 bigint 指针是否有效
            if bigint.is_null() {
                return Mpi::new(0);
            }

        // 如果没有 limbs，返回0
        if nblimbs == 0 {
            return Mpi::new(0);
        }

        // 手动读取数据而不是使用 slice，避免对齐问题
        // 将 32-bit limbs 转换为 64-bit limbs
        // 注意：存储顺序是 limb[0]=低32位, limb[1]=高32位, limb[2]=低32位, limb[3]=高32位...
        let mut data_vec = Vec::with_capacity((nblimbs + 1) / 2);
        let mut i = 0;
        while i < nblimbs {
            let low_ptr = bigint.add(2 + i) as *const u32;
            let low = if low_ptr.is_null() { 0 } else { *low_ptr };
            
            if i + 1 < nblimbs {
                // 有下一个 limb，合并两个 32-bit limbs 成一个 64-bit limb
                let high_ptr = bigint.add(2 + i + 1) as *const u32;
                let high = if high_ptr.is_null() { 0 } else { *high_ptr };
                
                // 合并：[high32][low32] -> 64-bit 
                // 根据存储格式：limb[0]=低32位, limb[1]=高32位
                // 所以组合为：high<<32 | low
                let combined = ((high as u64) << 32) | (low as u64);
                data_vec.push(combined as mbedtls_sys::mpi_uint);
                i += 2;
            } else {
                // 最后一个 limb，直接存储
                data_vec.push(low as mbedtls_sys::mpi_uint);
                i += 1;
            }
        }

        // 去除尾部的零值 limbs
        let trimmed_data = {
            let mut len = data_vec.len();
            while len > 0 && data_vec[len - 1] == 0 {
                len -= 1;
            }
            &data_vec[..len]
        };

        // 如果没有有效数据，返回0
        if trimmed_data.is_empty() {
            return Mpi::new(0);
        }

        // 创建一个新的 Mpi 实例
        let mut mpi = Mpi::new(0)?;

        // 使用安全的方法设置 MPI 值
        // 注意：这里假设底层库正确处理内存分配
        // 增长 MPI 以容纳所需数量的 limbs
        let handle: *mut mbedtls_sys::mpi = (&mut mpi).into();
        let result = mbedtls_sys::mpi_grow(handle, trimmed_data.len());
        if result != 0 {
            return Err(mbedtls::error::codes::MpiBadInputData.into());
        }

        // 设置符号
        (*handle).s = sign;

        // 复制数据，根据目标指针类型进行转换
        let dst_ptr = (*handle).p;
        std::ptr::copy_nonoverlapping(trimmed_data.as_ptr(), dst_ptr, trimmed_data.len());

        Ok(mpi)
        }
    }
}

// 为 Mpi 添加 get_limb 方法
trait MpiExt {
    fn get_limb(&self, n: usize) -> mbedtls_sys::mpi_uint;
}

impl MpiExt for Mpi {
    fn get_limb(&self, n: usize) -> mbedtls_sys::mpi_uint {
        let handle: *const mbedtls_sys::mpi = self.into();
        if n < unsafe { (*handle).n } {
            unsafe { *(*handle).p.offset(n as isize) }
        } else {
            // zero pad
            0
        }
    }
}

#[allow(non_camel_case_types)]
pub type TEE_BigInt = u32;
#[allow(non_camel_case_types)]
pub type TEE_BigIntFMM = u32;
#[allow(non_camel_case_types)]
pub type TEE_BigIntFMMContext = u32;


#[repr(C)]
struct BigintHdr {
    pub sign: i32,          // 对应 int32_t
    pub alloc_size: u16,    // 对应 uint16_t
    pub nblimbs: u16,       // 对应 uint16_t
}

pub const BIGINT_HDR_SIZE_IN_U32: usize = 2;

// 示例定义（您需要根据实际情况调整这些值）
const CFG_TA_BIGNUM_MAX_BITS: usize = 4096;
//const MBEDTLS_MPI_MAX_LIMBS: usize = 128;

// 错误码定义示例
type TeeResult = u32;
const TEE_SUCCESS: TeeResult = 0;
const TEE_ERROR_OVERFLOW: TeeResult = 1;
//const TEE_ERROR_SHORT_BUFFER: TeeResult = 2;


/// 初始化一个 TEE_BigInt 对象
/// 
/// 参数:
/// - big_int: 指向 TEE_BigInt 的指针
/// - len: 以 u32 为单位的长度
#[allow(non_camel_case_types,non_snake_case)]
pub unsafe fn TEE_BigIntInit(big_int: *mut TEE_BigInt, len: usize) {
    unsafe {
        // 检查长度是否超过限制
        if len > CFG_TA_BIGNUM_MAX_BITS / 4 {
            // PANIC 处理
            panic!("Too large bigint");
        }

        // 将整个区域清零（使用字节而不是 u32）
        core::ptr::write_bytes(big_int as *mut u8, 0, len * 4);

        // 设置头部信息
        let hdr = big_int as *mut BigintHdr;
        (*hdr).sign = 1;  // 设置符号位为正数(1表示正数)
        (*hdr).alloc_size = (len - BIGINT_HDR_SIZE_IN_U32) as u16;
        (*hdr).nblimbs = 0;  // 初始时没有有效数据
    }
}


/// 将八进制字符串转换为 TEE_BigInt
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - buffer: 源数据缓冲区指针
/// - buffer_len: 缓冲区长度
/// - sign: 符号值
/// 
/// 返回值:
/// - TeeResult: 转换结果
#[allow(non_camel_case_types,non_snake_case)]
pub fn TEE_BigIntConvertFromOctetString(
    dest: *mut TEE_BigInt,
    buffer: *const u8,
    buffer_len: usize,
    sign: i32,
) -> TeeResult {
    // 从二进制数据创建 MPI 对象
    let buffer_slice = unsafe { core::slice::from_raw_parts(buffer, buffer_len) };
    
    match Mpi::from_binary(buffer_slice) {
        Ok(mut mpi) => {
            // 如果符号为负，将 MPI 设置为负数
            if sign < 0 {
                match Mpi::new(-1) {
                    Ok(neg_one) => {
                        unsafe {
                            // 使用 mpi_mul_mpi 实现取负操作，通过 Into trait 获取内部引用
                            let result = mbedtls_sys::mpi_mul_mpi(
                                (&mut mpi).into(),
                                (&mpi).into(),
                                (&neg_one).into()
                            );
                            if result != 0 {
                                return TEE_ERROR_OVERFLOW;
                            }
                        }
                    },
                    Err(_) => return TEE_ERROR_OVERFLOW,
                }
            }
            
            // 获取目标缓冲区的分配大小
            unsafe {
                let hdr = dest as *mut BigintHdr;
                let alloc_size = (*hdr).alloc_size as usize;
                
                // 使用正确的 to_teebigint 方法进行转换
                match mpi.to_teebigint(dest, alloc_size) {
                    Ok(()) => TEE_SUCCESS,
                    Err(_) => TEE_ERROR_OVERFLOW,
                }
            }
        },
        Err(_) => TEE_ERROR_OVERFLOW,
    }
}



/// 将 TEE_BigInt 转换为八进制字符串（字节数组）
/// 
/// 参数:
/// - buffer: 目标缓冲区指针
/// - buffer_len: 缓冲区长度的指针（输入时为缓冲区大小，输出时为实际数据大小）
/// - big_int: 源 TEE_BigInt 指针
/// 
/// 返回值:
/// - TeeResult: 转换结果
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntConvertToOctetString(
    buffer: *mut u8,
    buffer_len: *mut usize,
    big_int: *const TEE_BigInt,
) -> TeeResult {
    // 检查输入参数
    if buffer_len.is_null() || big_int.is_null() {
        return TEE_ERROR_OVERFLOW; // 使用合适的错误码
    }
    
    // 从 TEE_BigInt 创建 MPI 对象，使用正确的方法
    let mpi = match unsafe { Mpi::from_teebigint(big_int) } {
        Ok(mpi) => mpi,
        Err(_) => return TEE_ERROR_OVERFLOW,
    };
    
    // 获取 MPI 的字节长度
    let sz = match mpi.byte_length() {
        Ok(len) => len,
        Err(_) => return TEE_ERROR_OVERFLOW,
    };
    
    // 检查缓冲区大小
    let provided_buffer_len = unsafe { *buffer_len };
    
    if sz <= provided_buffer_len {
        if !buffer.is_null() {
            // 写入二进制数据
            match mpi.to_binary() {
                Ok(binary_data) => {
                    // 复制数据到目标缓冲区
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            binary_data.as_ptr(),
                            buffer,
                            binary_data.len()
                        );
                    }
                },
                Err(_) => return TEE_ERROR_OVERFLOW,
            }
        }
    } else {
        // 缓冲区太小
        unsafe { *buffer_len = sz };
        return TEE_ERROR_OVERFLOW; // 应该使用 TEE_ERROR_SHORT_BUFFER
    }
    
    // 更新缓冲区长度
    unsafe { *buffer_len = sz };
    
    TEE_SUCCESS
}



/// 将 32 位有符号整数转换为 TEE_BigInt
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - short_val: 源 32 位有符号整数
#[allow(non_camel_case_types,non_snake_case)]
pub fn TEE_BigIntConvertFromS32(dest: *mut TEE_BigInt, short_val: i32) {
    unsafe {
        let hdr = dest as *mut BigintHdr;
        
        // 设置符号
        if short_val < 0 {
            (*hdr).sign = -1;
        } else {
            (*hdr).sign = 1;
        }
        
        // 获取绝对值
        let abs_val = if short_val < 0 {
            -(short_val as i64) as u32
        } else {
            short_val as u32
        };
        
        // 清零数据区域
        let data_ptr = dest.add(2) as *mut u32;
        let alloc_size = (*hdr).alloc_size as usize;
        for i in 0..alloc_size {
            *data_ptr.add(i) = 0;
        }
        
        // 设置值（如果没有空间，则至少设置第一个 limb）
        if alloc_size > 0 {
            *data_ptr = abs_val;
            (*hdr).nblimbs = if abs_val == 0 { 0 } else { 1 };
        } else {
            (*hdr).nblimbs = 0;
        }
    }
}


/// 将 TEE_BigInt 转换为 32 位有符号整数
/// 
/// 参数:
/// - dest: 目标 32 位有符号整数指针
/// - src: 源 TEE_BigInt 指针
/// 
/// 返回值:
/// - TeeResult: 转换结果
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntConvertToS32(dest: *mut i32, src: *const TEE_BigInt) -> TeeResult {
    // 从 TEE_BigInt 创建 MPI 对象，使用正确的方法
    let mpi = match unsafe { Mpi::from_teebigint(src) } {
        Ok(mpi) => mpi,
        Err(_) => return TEE_ERROR_OVERFLOW,
    };
    
    // 使用 Mpi 的 to_binary 方法获取二进制数据
    match mpi.to_binary() {
        Ok(binary_data) => {
            // 检查数据长度是否适合 32 位整数
            if binary_data.len() > 4 {
                return TEE_ERROR_OVERFLOW;
            }
            
            // 将二进制数据转换为 u32（大端序）
            let mut v: u32 = 0;
            for &byte in &binary_data {
                v = (v << 8) | byte as u32;
            }
            
            // 根据符号处理数值
            let result = if mpi.sign() == mbedtls::bignum::Sign::Positive {
                // 正数情况
                if v > i32::MAX as u32 {
                    TEE_ERROR_OVERFLOW
                } else {
                    unsafe {
                        *dest = v as i32;
                    }
                    TEE_SUCCESS
                }
            } else {
                // 负数情况
                let neg_v = (!v).wrapping_add(1); // 二进制补码
                if neg_v > i32::MAX as u32 + 1 {
                    TEE_ERROR_OVERFLOW
                } else {
                    unsafe {
                        *dest = -(neg_v as i32);
                    }
                    TEE_SUCCESS
                }
            };
            
            result
        },
        Err(_) => TEE_ERROR_OVERFLOW,
    }
}


/// 比较两个 TEE_BigInt 值
/// 
/// 参数:
/// - op1: 第一个 TEE_BigInt 指针
/// - op2: 第二个 TEE_BigInt 指针
/// 
/// 返回值:
/// - i32: 比较结果 (-1, 0, 或 1)
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntCmp(op1: *const TEE_BigInt, op2: *const TEE_BigInt) -> i32 {
    // 从 TEE_BigInt 创建 MPI 对象，使用正确的方法
    let mpi1 = match unsafe { Mpi::from_teebigint(op1) } {
        Ok(mpi) => mpi,
        Err(_) => return 0, // 出错时返回相等
    };
    
    let mpi2 = match unsafe { Mpi::from_teebigint(op2) } {
        Ok(mpi) => mpi,
        Err(_) => return 0, // 出错时返回相等
    };
    
    // 比较两个 Mpi 值
    match mpi1.cmp(&mpi2) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

/// 比较 TEE_BigInt 与 32 位有符号整数
/// 
/// 参数:
/// - src: TEE_BigInt 指针
/// - short_val: 32 位有符号整数
/// 
/// 返回值:
/// - i32: 比较结果 (-1, 0, 或 1)
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntCmpS32(src: *const TEE_BigInt, short_val: i32) -> i32 {
    // 从 TEE_BigInt 创建 MPI 对象
    let mpi = match unsafe { Mpi::from_teebigint(src) } {
        Ok(mpi) => mpi,
        Err(_) => return 0, // 出错时返回相等
    };
    
    // 创建用于比较的 MPI 对象
    let cmp_mpi = match Mpi::new(short_val as mpi_sint) {
        Ok(mpi) => mpi,
        Err(_) => return 0, // 出错时返回相等
    };
    
    // 比较两个 Mpi 值
    match mpi.cmp(&cmp_mpi) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

/// 将 TEE_BigInt 右移指定位数
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op: 源 TEE_BigInt 指针
/// - bits: 要右移的位数
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntShiftRight(dest: *mut TEE_BigInt, op: *const TEE_BigInt, bits: usize) {
    // 创建临时 MPI 对象来处理移位操作
    let mut temp_mpi = match unsafe { Mpi::from_teebigint(op) } {
        Ok(mpi) => mpi,
        Err(_) => return, // 如果转换失败则直接返回
    };
    
    // 执行移位操作
    temp_mpi.shr_assign(bits);
    
    // 将结果复制到目标
    let dest_info = unsafe {
        let hdr = dest as *mut BigintHdr;
        (*hdr).alloc_size as usize
    };
    
    // 将临时 MPI 转换为目标 TEE_BigInt
    unsafe {
        match temp_mpi.to_teebigint(dest, dest_info) {
            Ok(_) => {
                // 转换成功
            },
            Err(_) => {
                // 如果转换失败，至少确保目标被正确初始化为0
                let hdr = dest as *mut BigintHdr;
                (*hdr).sign = 0;
                (*hdr).nblimbs = 0;
                
                // 清零数据区域
                let data_ptr = dest.add(2) as *mut u32;
                for i in 0..dest_info {
                    *data_ptr.add(i) = 0;
                }
            }
        }
    }
}



/// 获取 TEE_BigInt 中指定位置的位值
/// 
/// 参数:
/// - src: 源 TEE_BigInt 指针
/// - bit_index: 位索引
/// 
/// 返回值:
/// - bool: 指定位的值
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntGetBit(src: *const TEE_BigInt, bit_index: u32) -> bool {
    // 从 TEE_BigInt 创建 MPI 对象
    let mpi = match unsafe { Mpi::from_teebigint(src) } {
        Ok(mpi) => mpi,
        Err(_) => return false, // 出错时返回 false
    };
    
    // 获取指定位的值
    mpi.get_bit(bit_index as usize)
}

/// 获取 TEE_BigInt 的位长度
/// 
/// 参数:
/// - src: 源 TEE_BigInt 指针
/// 
/// 返回值:
/// - u32: 位长度
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntGetBitCount(src: *const TEE_BigInt) -> u32 {
    // 从 TEE_BigInt 创建 MPI 对象
    let mpi = match unsafe { Mpi::from_teebigint(src) } {
        Ok(mpi) => mpi,
        Err(_) => return 0, // 出错时返回 0
    };
    
    // 获取位长度
    match mpi.bit_length() {
        Ok(len) => len as u32,
        Err(_) => 0, // 出错时返回 0
    }
}

/// 设置 TEE_BigInt 中指定位置的位值
/// 
/// 参数:
/// - op: 目标 TEE_BigInt 指针
/// - bit_index: 位索引
/// - value: 要设置的位值
/// 
/// 返回值:
/// - TeeResult: 操作结果
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntSetBit(op: *mut TEE_BigInt, bit_index: u32, value: bool) -> TeeResult {
    // 从 TEE_BigInt 创建 MPI 对象
    let mut mpi = match unsafe { Mpi::from_teebigint(op as *const TEE_BigInt) } {
        Ok(mpi) => mpi,
        Err(_) => return TEE_ERROR_OVERFLOW,
    };
    
    // 设置指定位的值
    match mpi.set_bit(bit_index as usize, value) {
        Ok(()) => {
            // 将结果复制回 TEE_BigInt
            unsafe {
                let hdr = op as *mut BigintHdr;
                let alloc_size = (*hdr).alloc_size as usize;
                
                match mpi.to_teebigint(op, alloc_size) {
                    Ok(()) => TEE_SUCCESS,
                    Err(_) => TEE_ERROR_OVERFLOW,
                }
            }
        },
        Err(_) => TEE_ERROR_OVERFLOW,
    }
}

/// 将一个 TEE_BigInt 的值赋给另一个 TEE_BigInt
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - src: 源 TEE_BigInt 指针
/// 
/// 返回值:
/// - TeeResult: 操作结果
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntAssign(dest: *mut TEE_BigInt, src: *const TEE_BigInt) -> TeeResult {
    // 检查是否为同一对象
    if dest == src as *mut TEE_BigInt {
        return TEE_SUCCESS;
    }
    
    // 检查空指针
    if dest.is_null() || src.is_null() {
        return TEE_ERROR_OVERFLOW;
    }
    
    unsafe {
        let src_hdr = src as *const BigintHdr;
        let dst_hdr = dest as *mut BigintHdr;
        
        // 检查目标分配大小是否足够
        if (*dst_hdr).alloc_size < (*src_hdr).nblimbs {
            return TEE_ERROR_OVERFLOW;
        }
        
        // 使用 slice 方式进行复制，避免直接指针操作
        let src_slice = core::slice::from_raw_parts(
            (src as *const u32).add(BIGINT_HDR_SIZE_IN_U32),
            (*src_hdr).nblimbs as usize
        );
        
        let dst_slice = core::slice::from_raw_parts_mut(
            dest.add(BIGINT_HDR_SIZE_IN_U32),
            (*src_hdr).nblimbs as usize
        );
        
        // 复制头部信息
        (*dst_hdr).nblimbs = (*src_hdr).nblimbs;
        (*dst_hdr).sign = (*src_hdr).sign;
        
        // 复制数据部分
        dst_slice.copy_from_slice(src_slice);
    }
    
    TEE_SUCCESS
}

/// 计算 TEE_BigInt 的绝对值
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - src: 源 TEE_BigInt 指针
/// 
/// 返回值:
/// - TeeResult: 操作结果
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntAbs(dest: *mut TEE_BigInt, src: *const TEE_BigInt) -> TeeResult {
    let res = TEE_BigIntAssign(dest, src);
    
    if res == TEE_SUCCESS {
        unsafe {
            let dst_hdr = dest as *mut BigintHdr;
            (*dst_hdr).sign = 1; // 设置为正数
        }
    }
    
    res
}

/// 执行两个 TEE_BigInt 的二元运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op1: 第一个操作数 TEE_BigInt 指针
/// - op2: 第二个操作数 TEE_BigInt 指针
/// - func: 执行实际运算的函数
#[allow(non_camel_case_types, non_snake_case, dead_code)]
fn bigint_binary(
    dest: *mut TEE_BigInt,
    op1: *const TEE_BigInt,
    op2: *const TEE_BigInt,
    func: unsafe extern "C" fn(*mut mbedtls_sys_auto::mpi, *const mbedtls_sys_auto::mpi, *const mbedtls_sys_auto::mpi) -> i32,
) -> TeeResult {
    unsafe {
        // 获取目标缓冲区信息
        let dst_hdr = dest as *mut BigintHdr;
        let alloc_size = (*dst_hdr).alloc_size as usize;
        
        // 从操作数创建 MPI 对象
        let mpi_op1 = if op1 == dest as *const TEE_BigInt {
            None // 稍后使用目标 MPI
        } else {
            match Mpi::from_teebigint(op1) {
                Ok(mpi) => Some(mpi),
                Err(_) => return TEE_ERROR_OVERFLOW,
            }
        };
        
        let mpi_op2 = if op2 == dest as *const TEE_BigInt {
            None // 稍后使用目标 MPI
        } else if op2 == op1 {
            mpi_op1.clone() // 复用第一个操作数
        } else {
            match Mpi::from_teebigint(op2) {
                Ok(mpi) => Some(mpi),
                Err(_) => return TEE_ERROR_OVERFLOW,
            }
        };
        
        // 从目标创建 MPI 对象或使用现有对象
        let mut mpi_dest = match Mpi::from_teebigint(dest as *const TEE_BigInt) {
            Ok(mpi) => mpi,
            Err(_) => return TEE_ERROR_OVERFLOW,
        };
        
        // 根据不同情况执行运算
        let result = if op1 == dest as *const TEE_BigInt && op2 == dest as *const TEE_BigInt {
            // op1 和 op2 都等于 dest，都使用目标 MPI
            func((&mut mpi_dest).into(), (&mpi_dest).into(), (&mpi_dest).into())
        } else if op1 == dest as *const TEE_BigInt {
            // 只有 op1 等于 dest
            if op2 == op1 {
                // op2 也等于 op1 (即 dest)
                func((&mut mpi_dest).into(), (&mpi_dest).into(), (&mpi_dest).into())
            } else {
                // op2 不等于 op1
                func((&mut mpi_dest).into(), (&mpi_dest).into(), mpi_op2.as_ref().unwrap().into())
            }
        } else if op2 == dest as *const TEE_BigInt {
            // 只有 op2 等于 dest
            func((&mut mpi_dest).into(), mpi_op1.as_ref().unwrap().into(), (&mpi_dest).into())
        } else {
            // op1 和 op2 都不等于 dest
            if op2 == op1 {
                // op2 复用 op1
                let op1_handle = mpi_op1.as_ref().unwrap().into();
                func((&mut mpi_dest).into(), op1_handle, op1_handle)
            } else {
                // op1 和 op2 都是独立的操作数
                func((&mut mpi_dest).into(), 
                     mpi_op1.as_ref().unwrap().into(), 
                     mpi_op2.as_ref().unwrap().into())
            }
        };
        
        if result != 0 {
            return TEE_ERROR_OVERFLOW;
        }
        
        // 将结果复制回目标 TEE_BigInt
        match mpi_dest.to_teebigint(dest, alloc_size) {
            Ok(()) => TEE_SUCCESS,
            Err(_) => TEE_ERROR_OVERFLOW,
        }
    }
}

/// 执行两个 TEE_BigInt 的模运算二元运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op1: 第一个操作数 TEE_BigInt 指针
/// - op2: 第二个操作数 TEE_BigInt 指针
/// - n: 模数 TEE_BigInt 指针
/// - func: 执行实际运算的函数
#[allow(non_camel_case_types, non_snake_case, dead_code)]
fn bigint_binary_mod(
    dest: *mut TEE_BigInt,
    op1: *const TEE_BigInt,
    op2: *const TEE_BigInt,
    n: *const TEE_BigInt,
    func: unsafe extern "C" fn(*mut mbedtls_sys_auto::mpi, *const mbedtls_sys_auto::mpi, *const mbedtls_sys_auto::mpi) -> i32,
) -> TeeResult {
    unsafe {
        // 检查模数是否有效（大于等于2）
        if TEE_BigIntCmpS32(n, 2) < 0 {
            panic!("Modulus is too short");
        }
        
        // 获取目标缓冲区信息
        let dst_hdr = dest as *mut BigintHdr;
        let alloc_size = (*dst_hdr).alloc_size as usize;
        
        // 从模数创建 MPI 对象
        let mpi_n = match Mpi::from_teebigint(n) {
            Ok(mpi) => mpi,
            Err(_) => return TEE_ERROR_OVERFLOW,
        };
        
        // 从操作数创建 MPI 对象
        let mpi_op1 = if op1 == dest as *const TEE_BigInt {
            None // 稍后使用目标 MPI
        } else {
            match Mpi::from_teebigint(op1) {
                Ok(mpi) => Some(mpi),
                Err(_) => return TEE_ERROR_OVERFLOW,
            }
        };
        
        let mpi_op2 = if op2 == dest as *const TEE_BigInt {
            None // 稍后使用目标 MPI
        } else if op2 == op1 {
            mpi_op1.clone() // 复用第一个操作数
        } else {
            match Mpi::from_teebigint(op2) {
                Ok(mpi) => Some(mpi),
                Err(_) => return TEE_ERROR_OVERFLOW,
            }
        };
        
        // 从目标创建 MPI 对象或使用现有对象
        let mut mpi_dest = match Mpi::from_teebigint(dest as *const TEE_BigInt) {
            Ok(mpi) => mpi,
            Err(_) => return TEE_ERROR_OVERFLOW,
        };
        
        // 创建临时 MPI 对象用于中间计算
        let mut mpi_t = match Mpi::new(0) {
            Ok(mpi) => mpi,
            Err(_) => return TEE_ERROR_OVERFLOW,
        };
        
        // 根据不同情况执行运算
        let result = if op1 == dest as *const TEE_BigInt && op2 == dest as *const TEE_BigInt {
            // op1 和 op2 都等于 dest，都使用目标 MPI
            func((&mut mpi_t).into(), (&mpi_dest).into(), (&mpi_dest).into())
        } else if op1 == dest as *const TEE_BigInt {
            // 只有 op1 等于 dest
            if op2 == op1 {
                // op2 也等于 op1 (即 dest)
                func((&mut mpi_t).into(), (&mpi_dest).into(), (&mpi_dest).into())
            } else {
                // op2 不等于 op1
                func((&mut mpi_t).into(), (&mpi_dest).into(), mpi_op2.as_ref().unwrap().into())
            }
        } else if op2 == dest as *const TEE_BigInt {
            // 只有 op2 等于 dest
            func((&mut mpi_t).into(), mpi_op1.as_ref().unwrap().into(), (&mpi_dest).into())
        } else {
            // op1 和 op2 都不等于 dest
            if op2 == op1 {
                // op2 复用 op1
                let op1_handle = mpi_op1.as_ref().unwrap().into();
                func((&mut mpi_t).into(), op1_handle, op1_handle)
            } else {
                // op1 和 op2 都是独立的操作数
                func((&mut mpi_t).into(), 
                     mpi_op1.as_ref().unwrap().into(), 
                     mpi_op2.as_ref().unwrap().into())
            }
        };
        
        if result != 0 {
            return TEE_ERROR_OVERFLOW;
        }
        
        // 执行模运算: mpi_dest = mpi_t % mpi_n
        let mod_result = mbedtls_sys::mpi_mod_mpi(
            (&mut mpi_dest).into(),
            (&mpi_t).into(),
            (&mpi_n).into()
        );
        
        if mod_result != 0 {
            return TEE_ERROR_OVERFLOW;
        }
        
        // 将结果复制回目标 TEE_BigInt
        match mpi_dest.to_teebigint(dest, alloc_size) {
            Ok(()) => TEE_SUCCESS,
            Err(_) => TEE_ERROR_OVERFLOW,
        }
    }
}

/// 对两个 TEE_BigInt 执行加法运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op1: 第一个操作数 TEE_BigInt 指针
/// - op2: 第二个操作数 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntAdd(dest: *mut TEE_BigInt, op1: *const TEE_BigInt, op2: *const TEE_BigInt) {
    let _ = bigint_binary(dest, op1, op2, mbedtls_sys_auto::mpi_add_mpi);
}

/// 对两个 TEE_BigInt 执行减法运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op1: 第一个操作数 TEE_BigInt 指针
/// - op2: 第二个操作数 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntSub(dest: *mut TEE_BigInt, op1: *const TEE_BigInt, op2: *const TEE_BigInt) {
    let _ = bigint_binary(dest, op1, op2, mbedtls_sys_auto::mpi_sub_mpi);
}

/// 对 TEE_BigInt 执行取负运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - src: 源 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntNeg(dest: *mut TEE_BigInt, src: *const TEE_BigInt) {
    unsafe {
        // 获取目标缓冲区信息
        let dst_hdr = dest as *mut BigintHdr;
        let alloc_size = (*dst_hdr).alloc_size as usize;
        
        // 从源创建 MPI 对象
        let mut mpi_src = if dest == src as *mut TEE_BigInt {
            // 如果源和目标相同，直接从目标创建 MPI 对象
            match Mpi::from_teebigint(src) {
                Ok(mpi) => mpi,
                Err(_) => return, // 出错时直接返回
            }
        } else {
            // 如果源和目标不同，从源创建 MPI 对象并复制到目标
            match Mpi::from_teebigint(src) {
                Ok(mpi) => mpi,
                Err(_) => return, // 出错时直接返回
            }
        };
        
        // 执行取负操作（改变符号）
        // 通过修改符号字段实现取负
        let handle: *mut mbedtls_sys::mpi = (&mut mpi_src).into();
        (*handle).s *= -1;
        
        // 将结果复制回目标 TEE_BigInt
        let _ = mpi_src.to_teebigint(dest, alloc_size);
    }
}


/// 计算所需的 TEE_BigInt 大小（以 u32 为单位）
/// 
/// 参数:
/// - n: 位数
/// 
/// 返回值:
/// - usize: 所需的 u32 数量
#[allow(non_camel_case_types, non_snake_case)]
fn tee_big_int_size_in_u32(n: usize) -> usize {
    ((n + 31) / 32) + BIGINT_HDR_SIZE_IN_U32
}

/// 计算两个 TEE_BigInt 的乘积
/// 
/// 参数:
/// - dest: 目标 TE_BigInt 指针
/// - op1: 第一个操作数 TEE_BigInt 指针
/// - op2: 第二个操作数 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntMul(dest: *mut TEE_BigInt, op1: *const TEE_BigInt, op2: *const TEE_BigInt) {
    unsafe {
        // 获取操作数的位数
        let bs1 = TEE_BigIntGetBitCount(op1);
        let bs2 = TEE_BigIntGetBitCount(op2);
        
        // 计算所需的空间大小
        let s = tee_big_int_size_in_u32(bs1 as usize) + tee_big_int_size_in_u32(bs2 as usize);
        
        // 分配临时缓冲区
        let mut tmp_storage = vec![0u32; s];
        let tmp = tmp_storage.as_mut_ptr();
        
        // 初始化临时缓冲区
        TEE_BigIntInit(tmp, s);
        
        // 执行乘法运算
        let _ = bigint_binary(tmp, op1, op2, mbedtls_sys_auto::mpi_mul_mpi);
        
        // 将结果复制到目标
        let zero_storage = [0u32; BIGINT_HDR_SIZE_IN_U32 + 1];
        let zero = zero_storage.as_ptr();
        TEE_BigIntInit(zero as *mut TEE_BigInt, BIGINT_HDR_SIZE_IN_U32 + 1);
        
        TEE_BigIntAdd(dest, tmp, zero);
        
        // tmp_storage 会自动释放
    }
}

/// 计算 TEE_BigInt 的平方
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op: 操作数 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntSquare(dest: *mut TEE_BigInt, op: *const TEE_BigInt) {
    // 平方就是自己乘以自己
    TEE_BigIntMul(dest, op, op);
}

/// 计算两个 TEE_BigInt 的除法运算
/// 
/// 参数:
/// - dest_q: 商的目标 TEE_BigInt 指针（可为空）
/// - dest_r: 余数的目标 TEE_BigInt 指针（可为空）
/// - op1: 被除数 TEE_BigInt 指针
/// - op2: 除数 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntDiv(
    dest_q: *mut TEE_BigInt,
    dest_r: *mut TEE_BigInt,
    op1: *const TEE_BigInt,
    op2: *const TEE_BigInt,
) {
    unsafe {
        // 检查除数是否为零
        let zero_check = Mpi::from_teebigint(op2);
        if let Ok(ref mpi_op2) = zero_check {
            // 检查是否为零值
            let is_zero = match mpi_op2.to_binary() {
                Ok(binary_data) => {
                    binary_data.iter().all(|&x| x == 0)
                },
                Err(_) => true // 出错时当作零处理以保证安全
            };
            
            if is_zero {
                panic!("Division by zero");
            }
        }
        
        // 获取目标缓冲区信息
        let q_alloc_size = if !dest_q.is_null() {
            let q_hdr = dest_q as *mut BigintHdr;
            Some((*q_hdr).alloc_size as usize)
        } else {
            None
        };
        
        let r_alloc_size = if !dest_r.is_null() {
            let r_hdr = dest_r as *mut BigintHdr;
            Some((*r_hdr).alloc_size as usize)
        } else {
            None
        };
        
        // 从操作数创建 MPI 对象
        let mpi_op1 = if op1 == dest_q || op1 == dest_r {
            // 如果操作数与目标相同，需要特殊处理
            match Mpi::from_teebigint(op1) {
                Ok(mpi) => mpi,
                Err(_) => return, // 出错时直接返回
            }
        } else {
            match Mpi::from_teebigint(op1) {
                Ok(mpi) => mpi,
                Err(_) => return, // 出错时直接返回
            }
        };
        
        let mpi_op2 = if op2 == op1 {
            // 复用第一个操作数
            mpi_op1.clone()
        } else if op2 == dest_q || op2 == dest_r {
            // 如果操作数与目标相同，需要特殊处理
            match Mpi::from_teebigint(op2) {
                Ok(mpi) => mpi,
                Err(_) => return, // 出错时直接返回
            }
        } else {
            match Mpi::from_teebigint(op2) {
                Ok(mpi) => mpi,
                Err(_) => return, // 出错时直接返回
            }
        };
        
        // 创建目标 MPI 对象
        let mut mpi_dest_q = match Mpi::new(0) {
            Ok(mpi) => mpi,
            Err(_) => return, // 出错时直接返回
        };
        
        let mut mpi_dest_r = match Mpi::new(0) {
            Ok(mpi) => mpi,
            Err(_) => return, // 出错时直接返回
        };
        
        // 执行除法运算
        let result = mbedtls_sys::mpi_div_mpi(
            (&mut mpi_dest_q).into(),
            (&mut mpi_dest_r).into(),
            (&mpi_op1).into(),
            (&mpi_op2).into()
        );
        
        if result != 0 {
            return; // 出错时直接返回
        }
        
        // 将结果复制回目标 TEE_BigInt
        if !dest_q.is_null() {
            let _ = mpi_dest_q.to_teebigint(dest_q, q_alloc_size.unwrap());
        }
        
        if !dest_r.is_null() {
            let _ = mpi_dest_r.to_teebigint(dest_r, r_alloc_size.unwrap());
        }
    }
}

/// 计算 TEE_BigInt 的模运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op: 操作数 TEE_BigInt 指针
/// - n: 模数 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntMod(dest: *mut TEE_BigInt, op: *const TEE_BigInt, n: *const TEE_BigInt) {
    // 检查模数是否有效（大于等于2）
    if TEE_BigIntCmpS32(n, 2) < 0 {
        panic!("Modulus is too short");
    }

    let _ = bigint_binary(dest, op, n, mbedtls_sys_auto::mpi_mod_mpi);
}

/// 计算两个 TEE_BigInt 的模加法运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op1: 第一个操作数 TEE_BigInt 指针
/// - op2: 第二个操作数 TEE_BigInt 指针
/// - n: 模数 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntAddMod(
    dest: *mut TEE_BigInt, 
    op1: *const TEE_BigInt, 
    op2: *const TEE_BigInt, 
    n: *const TEE_BigInt
) {
    let _ = bigint_binary_mod(dest, op1, op2, n, mbedtls_sys_auto::mpi_add_mpi);
}

/// 计算两个 TEE_BigInt 的模减法运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op1: 第一个操作数 TEE_BigInt 指针
/// - op2: 第二个操作数 TEE_BigInt 指针
/// - n: 模数 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntSubMod(
    dest: *mut TEE_BigInt, 
    op1: *const TEE_BigInt, 
    op2: *const TEE_BigInt, 
    n: *const TEE_BigInt
) {
    let _ = bigint_binary_mod(dest, op1, op2, n, mbedtls_sys_auto::mpi_sub_mpi);
}

/// 计算两个 TEE_BigInt 的模乘法运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op1: 第一个操作数 TEE_BigInt 指针
/// - op2: 第二个操作数 TEE_BigInt 指针
/// - n: 模数 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntMulMod(
    dest: *mut TEE_BigInt, 
    op1: *const TEE_BigInt, 
    op2: *const TEE_BigInt, 
    n: *const TEE_BigInt
) {
    let _ = bigint_binary_mod(dest, op1, op2, n, mbedtls_sys_auto::mpi_mul_mpi);
}

/// 计算 TEE_BigInt 的模平方运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op: 操作数 TEE_BigInt 指针
/// - n: 模数 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntSquareMod(
    dest: *mut TEE_BigInt, 
    op: *const TEE_BigInt, 
    n: *const TEE_BigInt
) {
    // 平方模运算就是自己与自己做模乘法
    TEE_BigIntMulMod(dest, op, op, n);
}

/// 计算 TEE_BigInt 的模逆运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op: 操作数 TEE_BigInt 指针
/// - n: 模数 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntInvMod(dest: *mut TEE_BigInt, op: *const TEE_BigInt, n: *const TEE_BigInt) {
    // 检查模数是否有效（大于等于2）以及操作数是否为零
    if TEE_BigIntCmpS32(n, 2) < 0 || TEE_BigIntCmpS32(op, 0) == 0 {
        panic!("too small modulus or trying to invert zero");
    }

    unsafe {
        // 获取目标缓冲区信息
        let dst_hdr = dest as *mut BigintHdr;
        let alloc_size = (*dst_hdr).alloc_size as usize;
        
        // 从模数创建 MPI 对象
        let mpi_n = match Mpi::from_teebigint(n) {
            Ok(mpi) => mpi,
            Err(_) => return, // 出错时直接返回
        };
        
        // 从操作数创建 MPI 对象
        let mpi_op = if op == dest as *const TEE_BigInt {
            // 如果操作数与目标相同，直接从目标创建 MPI 对象
            match Mpi::from_teebigint(op) {
                Ok(mpi) => mpi,
                Err(_) => return, // 出错时直接返回
            }
        } else {
            // 如果操作数与目标不同
            match Mpi::from_teebigint(op) {
                Ok(mpi) => mpi,
                Err(_) => return, // 出错时直接返回
            }
        };
        
        // 创建目标 MPI 对象
        let mut mpi_dest = match Mpi::new(0) {
            Ok(mpi) => mpi,
            Err(_) => return, // 出错时直接返回
        };
        
        // 执行模逆运算
        let result = mbedtls_sys::mpi_inv_mod(
            (&mut mpi_dest).into(),
            (&mpi_op).into(),
            (&mpi_n).into()
        );
        
        if result != 0 {
            return; // 出错时直接返回
        }
        
        // 将结果复制回目标 TEE_BigInt
        let _ = mpi_dest.to_teebigint(dest, alloc_size);
    }
}

/// 判断 TEE_BigInt 是否为奇数
/// 
/// 参数:
/// - src: TEE_BigInt 指针
/// 
/// 返回值:
/// - bool: 如果是奇数返回true，否则返回false
#[allow(non_camel_case_types, non_snake_case)]
fn tee_bigint_is_odd(src: *const TEE_BigInt) -> bool {
    // 获取最低位的值来判断奇偶性
    TEE_BigIntGetBit(src, 0)
}

/// 判断 TEE_BigInt 是否为偶数
/// 
/// 参数:
/// - src: TEE_BigInt 指针
/// 
/// 返回值:
/// - bool: 如果是偶数返回true，否则返回false
#[allow(non_camel_case_types, non_snake_case)]
fn tee_bigint_is_even(src: *const TEE_BigInt) -> bool {
    !tee_bigint_is_odd(src)
}

/// 计算 TEE_BigInt 的模幂运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - op1: 底数 TEE_BigInt 指针
/// - op2: 指数 TEE_BigInt 指针
/// - n: 模数 TEE_BigInt 指针
/// - context: FMM 上下文指针（未使用）
/// 
/// 返回值:
/// - TeeResult: 操作结果
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntExpMod(
    dest: *mut TEE_BigInt,
    op1: *const TEE_BigInt,
    op2: *const TEE_BigInt,
    n: *const TEE_BigInt,
    _context: *const TEE_BigIntFMMContext,
) -> TeeResult {
    // 检查模数是否有效（大于等于2）
    if TEE_BigIntCmpS32(n, 2) <= 0 {
        panic!("too small modulus");
    }
    
    // 检查模数是否为奇数
    if tee_bigint_is_even(n) {
        return TEE_ERROR_OVERFLOW; // 使用合适的错误码替代 TEE_ERROR_NOT_SUPPORTED
    }

    unsafe {
        // 获取目标缓冲区信息
        let dst_hdr = dest as *mut BigintHdr;
        let alloc_size = (*dst_hdr).alloc_size as usize;
        
        // 从模数创建 MPI 对象
        let mpi_n = match Mpi::from_teebigint(n) {
            Ok(mpi) => mpi,
            Err(_) => return TEE_ERROR_OVERFLOW,
        };
        
        // 从底数创建 MPI 对象
        let mpi_op1 = if op1 == dest as *const TEE_BigInt {
            // 如果底数与目标相同，直接从目标创建 MPI 对象
            match Mpi::from_teebigint(op1) {
                Ok(mpi) => mpi,
                Err(_) => return TEE_ERROR_OVERFLOW,
            }
        } else {
            // 如果底数与目标不同
            match Mpi::from_teebigint(op1) {
                Ok(mpi) => mpi,
                Err(_) => return TEE_ERROR_OVERFLOW,
            }
        };
        
        // 从指数创建 MPI 对象
        let mpi_op2 = if op2 == dest as *const TEE_BigInt {
            // 如果指数与目标相同，直接从目标创建 MPI 对象
            match Mpi::from_teebigint(op2) {
                Ok(mpi) => mpi,
                Err(_) => return TEE_ERROR_OVERFLOW,
            }
        } else if op2 == op1 {
            // 如果指数与底数相同，复用底数的MPI对象
            mpi_op1.clone()
        } else {
            // 如果指数与底数、目标都不同
            match Mpi::from_teebigint(op2) {
                Ok(mpi) => mpi,
                Err(_) => return TEE_ERROR_OVERFLOW,
            }
        };
        
        // 创建目标 MPI 对象
        let mut mpi_dest = match Mpi::new(0) {
            Ok(mpi) => mpi,
            Err(_) => return TEE_ERROR_OVERFLOW,
        };
        
        // 执行模幂运算
        let result = mbedtls_sys::mpi_exp_mod(
            (&mut mpi_dest).into(),
            (&mpi_op1).into(),
            (&mpi_op2).into(),
            (&mpi_n).into(),
            core::ptr::null_mut(), // context参数为NULL
        );
        
        if result != 0 {
            return TEE_ERROR_OVERFLOW;
        }
        
        // 将结果复制回目标 TEE_BigInt
        match mpi_dest.to_teebigint(dest, alloc_size) {
            Ok(()) => TEE_SUCCESS,
            Err(_) => TEE_ERROR_OVERFLOW,
        }
    }
}

/// 判断两个 TEE_BigInt 是否互质
/// 
/// 参数:
/// - op1: 第一个 TEE_BigInt 指针
/// - op2: 第二个 TEE_BigInt 指针
/// 
/// 返回值:
/// - bool: 如果互质返回true，否则返回false
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntRelativePrime(op1: *const TEE_BigInt, op2: *const TEE_BigInt) -> bool {
    unsafe {
        // 从第一个操作数创建 MPI 对象
        let mpi_op1 = match Mpi::from_teebigint(op1) {
            Ok(mpi) => mpi,
            Err(_) => return false, // 出错时返回false
        };
        
        // 从第二个操作数创建 MPI 对象
        let mpi_op2 = if op2 == op1 {
            // 如果两个操作数相同，复用第一个MPI对象
            mpi_op1.clone()
        } else {
            match Mpi::from_teebigint(op2) {
                Ok(mpi) => mpi,
                Err(_) => return false, // 出错时返回false
            }
        };
        
        // 创建用于计算GCD的MPI对象
        let mut gcd = match Mpi::new(0) {
            Ok(mpi) => mpi,
            Err(_) => return false, // 出错时返回false
        };
        
        // 计算最大公约数
        let result = mbedtls_sys::mpi_gcd(
            (&mut gcd).into(),
            (&mpi_op1).into(),
            (&mpi_op2).into()
        );
        
        if result != 0 {
            return false; // 出错时返回false
        }
        
        // 检查GCD是否为1（互质的定义）
        // 使用现有的比较函数来比较GCD与1
        match Mpi::new(1) {
            Ok(one) => {
                match gcd.cmp(&one) {
                    std::cmp::Ordering::Equal => true,   // GCD为1，互质
                    _ => false                           // GCD不为1，不互质
                }
            },
            Err(_) => false // 出错时返回false
        }
    }
}


/// 计算两个 TEE_BigInt 的扩展最大公约数
/// 
/// 参数:
/// - gcd: 最大公约数的目标 TEE_BigInt 指针
/// - u: 系数u的目标 TEE_BigInt 指针（可为空）
/// - v: 系数v的目标 TEE_BigInt 指针（可为空）
/// - op1: 第一个操作数 TEE_BigInt 指针
/// - op2: 第二个操作数 TEE_BigInt 指针
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntComputeExtendedGcd(
    gcd: *mut TEE_BigInt,
    u: *mut TEE_BigInt,
    v: *mut TEE_BigInt,
    op1: *const TEE_BigInt,
    op2: *const TEE_BigInt,
) {
    // 检查必要参数
    if gcd.is_null() || op1.is_null() || op2.is_null() {
        return;
    }

    unsafe {
        // 从操作数创建 MPI 对象
        let mpi_op1 = match Mpi::from_teebigint(op1) {
            Ok(mpi) => mpi,
            Err(_) => return,
        };
        
        let mpi_op2 = if op2 == op1 {
            mpi_op1.clone()
        } else {
            match Mpi::from_teebigint(op2) {
                Ok(mpi) => mpi,
                Err(_) => return,
            }
        };

        // 如果不需要计算系数u和v，直接使用内置GCD函数
        if u.is_null() && v.is_null() {
            let mut mpi_gcd = match Mpi::new(0) {
                Ok(mpi) => mpi,
                Err(_) => return,
            };
            
            let result = mbedtls_sys::mpi_gcd(
                (&mut mpi_gcd).into(),
                (&mpi_op1).into(),
                (&mpi_op2).into()
            );
            
            if result != 0 {
                return;
            }
            
            // 将结果复制回目标 TEE_BigInt
            let hdr = gcd as *mut BigintHdr;
            let alloc_size = (*hdr).alloc_size as usize;
            let _ = mpi_gcd.to_teebigint(gcd, alloc_size);
            return;
        }

        // 需要计算系数，执行扩展欧几里得算法
        let s1 = mpi_op1.sign();
        let s2 = mpi_op2.sign();
        
        // 使用绝对值进行计算（通过创建新正值MPI代替set_sign）
        let abs_op1 = mpi_abs_value(&mpi_op1);
        let abs_op2 = mpi_abs_value(&mpi_op2);
        
        let cmp = abs_op1.cmp(&abs_op2);
        
        let (mpi_gcd, mpi_u, mpi_v) = match cmp {  // 移除了mut
            std::cmp::Ordering::Equal => {
                // 两数相等的情况
                let gcd_result = abs_op1;
                let u_result = match Mpi::new(1) {
                    Ok(mpi) => mpi,
                    Err(_) => return,
                };
                let v_result = match Mpi::new(0) {
                    Ok(mpi) => mpi,
                    Err(_) => return,
                };
                (gcd_result, u_result, v_result)
            },
            std::cmp::Ordering::Greater => {
                extended_gcd_algorithm(&abs_op1, &abs_op2)
            },
            std::cmp::Ordering::Less => {
                // op1 < op2，交换参数
                let (gcd_result, v_result, u_result) = extended_gcd_algorithm(&abs_op2, &abs_op1);
                (gcd_result, u_result, v_result)
            },
        };
        
        // 根据原始符号调整系数（使用negate_mpi_safe代替neg方法）
        let final_mpi_u = if s1 == mbedtls::bignum::Sign::Negative {
            negate_mpi_safe(&mpi_u)
        } else {
            mpi_u
        };
        
        let final_mpi_v = if s2 == mbedtls::bignum::Sign::Negative {
            negate_mpi_safe(&mpi_v)
        } else {
            mpi_v
        };
        
        // 将结果复制回目标 TEE_BigInt
        if !u.is_null() {
            let hdr = u as *mut BigintHdr;
            let alloc_size = (*hdr).alloc_size as usize;
            let _ = final_mpi_u.to_teebigint(u, alloc_size);
        }
        
        if !v.is_null() {
            let hdr = v as *mut BigintHdr;
            let alloc_size = (*hdr).alloc_size as usize;
            let _ = final_mpi_v.to_teebigint(v, alloc_size);
        }
        
        let hdr = gcd as *mut BigintHdr;
        let alloc_size = (*hdr).alloc_size as usize;
        let _ = mpi_gcd.to_teebigint(gcd, alloc_size);
    }
}

/// 获取MPI的绝对值（创建一个新的正值MPI）
fn mpi_abs_value(mpi: &Mpi) -> Mpi {
    let mut result = mpi.clone();
    // 强制设置为正数
    unsafe {
        let handle: *mut mbedtls_sys::mpi = (&mut result).into();
        (*handle).s = 1;
    }
    result
}

/// 对MPI取负值
fn negate_mpi_safe(mpi: &Mpi) -> Mpi {
    let mut result = mpi.clone();
    // 改变符号
    unsafe {
        let handle: *mut mbedtls_sys::mpi = (&mut result).into();
        (*handle).s *= -1;
    }
    result
}

/// 扩展欧几里得算法实现
/// 
/// 参数:
/// - x: 较大的数
/// - y: 较小的数
/// 
/// 返回值:
/// - (gcd, a, b) 满足 ax + by = gcd(x,y)
#[allow(non_camel_case_types, non_snake_case)]
fn extended_gcd_algorithm(x: &Mpi, y: &Mpi) -> (Mpi, Mpi, Mpi) {
    // 安全检查
    if let (Ok(x_binary), Ok(y_binary)) = (x.to_binary(), y.to_binary()) {
        if x_binary.iter().all(|&b| b == 0) || y_binary.iter().all(|&b| b == 0) {
            // 处理零值情况
            return (
                Mpi::new(0).unwrap_or_else(|_| Mpi::new(0).expect("Failed to create Mpi")),
                Mpi::new(0).unwrap_or_else(|_| Mpi::new(0).expect("Failed to create Mpi")),
                Mpi::new(0).unwrap_or_else(|_| Mpi::new(0).expect("Failed to create Mpi"))
            );
        }
    }
    
    let mut u = x.clone();
    let mut v = y.clone();
    
    // 初始化系数矩阵
    let mut a = Mpi::new(1).expect("Failed to create Mpi");
    let mut b = Mpi::new(0).expect("Failed to create Mpi");
    let mut c = Mpi::new(0).expect("Failed to create Mpi");
    let mut d = Mpi::new(1).expect("Failed to create Mpi");
    
    // 计算公共因子2^k
    let mut k = 0;
    while mpi_is_even(&u) && mpi_is_even(&v) {
        k += 1;
        u = (&u >> 1).expect("Shift operation failed");
        v = (&v >> 1).expect("Shift operation failed");
    }
    
    let mut x_copy = u.clone();
    let mut y_copy = v.clone();
    
    // 主循环
    while !is_mpi_zero(&x_copy) {
        while mpi_is_even(&x_copy) {
            x_copy = (&x_copy >> 1).expect("Shift operation failed");
// ...
            
            if mpi_is_odd(&a) || mpi_is_odd(&b) {
                a = add_mpi_safe(&a, &y_copy);
                b = sub_mpi_safe(&b, &u);
            }
            
            a = (&a >> 1).expect("Shift operation failed");
            b = (&b >> 1).expect("Shift operation failed");
        }
        
        while mpi_is_even(&y_copy) {
            y_copy = (&y_copy >> 1).expect("Shift operation failed");
            
            if mpi_is_odd(&c) || mpi_is_odd(&d) {
                c = add_mpi_safe(&c, &y_copy);
                d = sub_mpi_safe(&d, &u);
            }
            
            c = (&c >> 1).expect("Shift operation failed");
            d = (&d >> 1).expect("Shift operation failed");
        }
        
        match x_copy.cmp(&y_copy) {
            std::cmp::Ordering::Greater | std::cmp::Ordering::Equal => {
                x_copy = sub_mpi_safe(&x_copy, &y_copy);
                a = sub_mpi_safe(&a, &c);
                b = sub_mpi_safe(&b, &d);
            },
            std::cmp::Ordering::Less => {
                y_copy = sub_mpi_safe(&y_copy, &x_copy);
                c = sub_mpi_safe(&c, &a);
                d = sub_mpi_safe(&d, &b);
            },
        }
    }
    
    // 左移k位恢复公共因子
    let gcd = (&y_copy << k).expect("Shift operation failed");
    
    (gcd, c, d)
}

/// 安全的MPI加法
fn add_mpi_safe(op1: &Mpi, op2: &Mpi) -> Mpi {
    let mut result = Mpi::new(0).expect("Failed to create Mpi");
    let ret = unsafe {
        mbedtls_sys::mpi_add_mpi(
            (&mut result).into(),
            op1.into(),
            op2.into()
        )
    };
    
    if ret == 0 {
        result
    } else {
        Mpi::new(0).expect("Failed to create Mpi")
    }
}

/// 安全的MPI减法
fn sub_mpi_safe(op1: &Mpi, op2: &Mpi) -> Mpi {
    let mut result = Mpi::new(0).expect("Failed to create Mpi");
    let ret = unsafe {
        mbedtls_sys::mpi_sub_mpi(
            (&mut result).into(),
            op1.into(),
            op2.into()
        )
    };
    
    if ret == 0 {
        result
    } else {
        Mpi::new(0).expect("Failed to create Mpi")
    }
}



/// 检查MPI是否为零
fn is_mpi_zero(mpi: &Mpi) -> bool {
    match mpi.to_binary() {
        Ok(data) => data.iter().all(|&b| b == 0),
        Err(_) => true
    }
}

/// 检查MPI是否为偶数
fn mpi_is_even(mpi: &Mpi) -> bool {
    match mpi.to_binary() {
        Ok(data) => {
            if data.is_empty() {
                true
            } else {
                (data[data.len() - 1] & 1) == 0
            }
        },
        Err(_) => true
    }
}

/// 检查MPI是否为奇数
fn mpi_is_odd(mpi: &Mpi) -> bool {
    !mpi_is_even(mpi)
}

/// 检查 TEE_BigInt 是否可能是素数
/// 
/// 参数:
/// - op: 要检查的 TEE_BigInt 指针
/// - confidenceLevel: 置信水平（最小为80）
/// 
/// 返回值:
/// - i32: 1表示可能是素数，0表示不是素数
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntIsProbablePrime(op: *const TEE_BigInt, confidenceLevel: u32) -> i32 {
    // 检查输入参数
    if op.is_null() {
        return 0;
    }

    // 从 TEE_BigInt 创建 MPI 对象
    let mpi = match unsafe { Mpi::from_teebigint(op) } {
        Ok(mpi) => mpi,
        Err(_) => return 0,
    };

    // 使用至少80轮测试确保准确性
    let rounds = confidenceLevel.max(80);

    // 创建一个符合 RngCallback 要求的结构体
    struct TeeRng;
    
    impl RngCallback for TeeRng {
        unsafe extern "C" fn call(
            _user_data: *mut mbedtls_sys_auto::types::raw_types::c_void,
            data: *mut u8,
            len: usize,
        ) -> i32 {
            // 在实际实现中，这里应该调用真正的随机数生成器
            // 作为示例，我们使用简单的方式填充数据
            unsafe {
                for i in 0..len {
                    *data.add(i) = (i % 256) as u8;
                }
            }
            0 // 成功
        }
        
        fn data_ptr(&self) -> *mut mbedtls_sys_auto::types::raw_types::c_void {
            core::ptr::null_mut()
        }
    }

    // 创建 RNG 实例并执行素性测试
    let mut rng = TeeRng;
    match mpi.is_probably_prime(rounds, &mut rng) {
        Ok(()) => 1,   // 通过素性测试，可能是素数
        Err(_) => 0,   // 未通过素性测试，不是素数
    }
}

/// 初始化一个 TEE_BigIntFMM 对象
/// 
/// 参数:
/// - big_int_fmm: 指向 TEE_BigIntFMM 的指针
/// - len: 以 u32 为单位的长度
#[allow(non_camel_case_types, non_snake_case)]
pub unsafe fn TEE_BigIntInitFMM(big_int_fmm: *mut TEE_BigIntFMM, len: usize) {
    unsafe {
        TEE_BigIntInit(big_int_fmm, len);
    }
}

/// 初始化一个 TEE_BigIntFMMContext 对象 (带返回值版本)
/// 
/// 参数:
/// - context: 指向 TEE_BigIntFMMContext 的指针
/// - len: 以 u32 为单位的长度
/// - modulus: 模数 TEE_BigInt 指针
/// 
/// 返回值:
/// - TeeResult: 操作结果
#[allow(non_camel_case_types, non_snake_case)]
pub unsafe fn TEE_BigIntInitFMMContext1(
    context: *mut TEE_BigIntFMMContext,
    len: usize,
    modulus: *const TEE_BigInt,
) -> TeeResult {
    // 仅保留参数签名并返回成功
    let _ = context;
    let _ = len;
    let _ = modulus;
    TEE_SUCCESS
}

/// 计算所需的 TEE_BigIntFMM 大小（以 u32 为单位）
/// 
/// 参数:
/// - modulus_size_in_bits: 模数的位数
/// 
/// 返回值:
/// - usize: 所需的 u32 数量
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntFMMSizeInU32(modulus_size_in_bits: usize) -> usize {
    // 复用已有的 TEE_BigIntSizeInU32 函数逻辑
    tee_big_int_size_in_u32(modulus_size_in_bits)
}


/// 计算所需的 TEE_BigIntFMMContext 大小（以 u32 为单位）
/// 
/// 参数:
/// - modulus_size_in_bits: 模数的位数
/// 
/// 返回值:
/// - usize: 所需的 u32 数量
#[allow(non_camel_case_types, non_snake_case)]
pub fn TEE_BigIntFMMContextSizeInU32(modulus_size_in_bits: usize) -> usize {
    // 返回大于0的值以使 malloc 等函数正常工作
    let _ = modulus_size_in_bits; // 未使用参数
    1
}


/// 将 TEE_BigInt 转换为 TEE_BigIntFMM
/// 
/// 参数:
/// - dest: 目标 TEE_BigIntFMM 指针
/// - src: 源 TEE_BigInt 指针
/// - n: 模数 TEE_BigInt 指针
/// - context: FMM 上下文指针（未使用）
#[allow(non_camel_case_types, non_snake_case)]
pub unsafe fn TEE_BigIntConvertToFMM(
    dest: *mut TEE_BigIntFMM,
    src: *const TEE_BigInt,
    n: *const TEE_BigInt,
    context: *const TEE_BigIntFMMContext,
) {
    // 调用 TEE_BigIntMod 函数
    let _ = context; // 未使用的参数
    TEE_BigIntMod(dest as *mut TEE_BigInt, src, n);
}

/// 将 TEE_BigIntFMM 转换为 TEE_BigInt
/// 
/// 参数:
/// - dest: 目标 TEE_BigInt 指针
/// - src: 源 TEE_BigIntFMM 指针
/// - n: 模数 TEE_BigInt 指针（未使用）
/// - context: FMM 上下文指针（未使用）
#[allow(non_camel_case_types, non_snake_case)]
pub unsafe fn TEE_BigIntConvertFromFMM(
    dest: *mut TEE_BigInt,
    src: *const TEE_BigIntFMM,
    n: *const TEE_BigInt,
    context: *const TEE_BigIntFMMContext,
) {
    // 因为 TEE_BigIntFMM 和 TEE_BigInt 都是 u32 类型别名，所以可以直接复制
    
    // 检查空指针
    if dest.is_null() || src.is_null() {
        return;
    }
    
    // 从源创建 MPI 对象
    let mpi_src = match unsafe { Mpi::from_teebigint(src as *const TEE_BigInt) } {
        Ok(mpi) => mpi,
        Err(_) => return,
    };
    
    // 获取目标缓冲区信息
    let hdr = dest as *mut BigintHdr;
    let alloc_size = unsafe { (*hdr).alloc_size as usize };
    
    // 将源 MPI 复制到目标 TEE_BigInt
    let _ = unsafe { mpi_src.to_teebigint(dest, alloc_size) };
    
    // 未使用的参数
    let _ = n;
    let _ = context;
}

/// 计算 TEE_BigIntFMM 的快速模乘运算
/// 
/// 参数:
/// - dest: 目标 TEE_BigIntFMM 指针
/// - op1: 第一个操作数 TEE_BigIntFMM 指针
/// - op2: 第二个操作数 TEE_BigIntFMM 指针
/// - n: 模数 TEE_BigInt 指针
/// - context: FMM 上下文指针（未使用）
#[allow(non_camel_case_types, non_snake_case)]
pub unsafe fn TEE_BigIntComputeFMM(
    dest: *mut TEE_BigIntFMM,
    op1: *const TEE_BigIntFMM,
    op2: *const TEE_BigIntFMM,
    n: *const TEE_BigInt,
    context: *const TEE_BigIntFMMContext,
) {
    // 检查必要的参数
    if dest.is_null() || op1.is_null() || op2.is_null() || n.is_null() {
        return;
    }
    
    // 未使用的参数
    let _ = context;
    
    // 从操作数创建 MPI 对象
    let mpi_op1 = match unsafe { Mpi::from_teebigint(op1 as *const TEE_BigInt) } {
        Ok(mpi) => mpi,
        Err(_) => return,
    };
    
    let mpi_op2 = if op2 as *const TEE_BigInt == op1 as *const TEE_BigInt {
        // 复用第一个操作数
        mpi_op1.clone()
    } else {
        match unsafe { Mpi::from_teebigint(op2 as *const TEE_BigInt) } {
            Ok(mpi) => mpi,
            Err(_) => return,
        }
    };
    
    let mpi_n = match unsafe { Mpi::from_teebigint(n) } {
        Ok(mpi) => mpi,
        Err(_) => return,
    };
    
    // 创建临时 MPI 对象用于中间计算
    let mut mpi_t = match Mpi::new(0) {
        Ok(mpi) => mpi,
        Err(_) => return,
    };
    
    // 执行乘法运算: mpi_t = mpi_op1 * mpi_op2
    let mul_result = unsafe { mbedtls_sys::mpi_mul_mpi(
        (&mut mpi_t).into(),
        (&mpi_op1).into(),
        (&mpi_op2).into()
    ) };
    
    if mul_result != 0 {
        return;
    }
    
    // 获取目标缓冲区信息
    let dst_hdr = dest as *mut BigintHdr;
    let alloc_size = unsafe { (*dst_hdr).alloc_size as usize };
    
    // 执行模运算: dest = mpi_t % mpi_n
    let mod_result = unsafe { mbedtls_sys::mpi_mod_mpi(
        (&mut mpi_t).into(),  // 我们可以重用 mpi_t 作为目标
        (&mpi_t).into(),      // 被模数
        (&mpi_n).into()       // 模数
    ) };
    
    if mod_result != 0 {
        return;
    }
    
    // 将结果复制回目标 TEE_BigIntFMM
    let _ = unsafe { mpi_t.to_teebigint(dest as *mut TEE_BigInt, alloc_size) };
}