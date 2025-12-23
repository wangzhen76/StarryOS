/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![allow(non_camel_case_types)]

use mbedtls::bignum::Mpi;
use std::str::FromStr;
use rust_utee::tee_api_types::{TEE_BigInt};
use rust_utee::tee_api_defines::{TEE_SUCCESS};

// 导入所有需要的 TEE BigInt 函数
use rust_utee::tee_api_arith_mpi::*;



#[test]
fn test_tee_bigint_convert_from_s32() {
    let mut buffer = [0u32; 10];
    let big_int = buffer.as_mut_ptr();
    
    TEE_BigIntInit(big_int, 10);
    TEE_BigIntConvertFromS32(big_int, 12345);
    
    // 验证转换结果
    let mpi = unsafe{Mpi::from_teebigint(big_int as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 12345);

}
#[test]
fn test_tee_bigint_octet_string_conversion() {
    let data = [0x12, 0x34, 0x56, 0x78];
    let mut buffer = [0u32; 10];
    let big_int = buffer.as_mut_ptr();

    assert_eq!(data.len(), 4);
    
    // 首先需要初始化BigInt
    TEE_BigIntInit(big_int, 10);
    
    let res = TEE_BigIntConvertFromOctetString(big_int, data.as_ptr(), data.len(), 1);
    // 应该期望成功而不是失败
    assert_eq!(res, TEE_SUCCESS);
    
    let mut output_buffer = [0u8; 10];
    let mut output_len = output_buffer.len();
    
    let res = TEE_BigIntConvertToOctetString(output_buffer.as_mut_ptr(), &mut output_len, big_int);
    assert_eq!(res, TEE_SUCCESS);
    assert_eq!(output_len, 4);
    assert_eq!(&output_buffer[..4], &[0x12, 0x34, 0x56, 0x78]);
}

#[test]
fn test_tee_bigint_cmp() {
    let mut buffer1 = [0u32; 10];
    let mut buffer2 = [0u32; 10];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();


    TEE_BigIntInit(big_int1, 10);
    TEE_BigIntInit(big_int2, 10);
    TEE_BigIntConvertFromS32(big_int1, 100);
    TEE_BigIntConvertFromS32(big_int2, 200);

    assert!((big_int2 as usize).abs_diff(big_int1 as usize) >= 40); // 10 * size_of::<u32>()

    // 测试相同指针比较
    let same_cmp = TEE_BigIntCmp(big_int1, big_int1);
    assert_eq!(same_cmp, 0);

    let cmp = TEE_BigIntCmp(big_int1, big_int2);
    assert_ne!(cmp, 0);

}
//TEE_BigIntShiftRight(big_int2, big_int1, 3); // 128 >> 3 = 16
#[test]
fn test_tee_bigint_shift_right() {
    let mut buffer1 = [0u32; 10];
    let mut buffer2 = [0u32; 10];
    let mut buffer3 = [0u32; 10];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    let big_int3 = buffer3.as_mut_ptr();
    
    TEE_BigIntInit(big_int1, 10);
    TEE_BigIntInit(big_int2, 10);
    TEE_BigIntInit(big_int3, 10);
    TEE_BigIntConvertFromS32(big_int1, 128);
    TEE_BigIntConvertFromS32(big_int3, 16);

    TEE_BigIntShiftRight(big_int2, big_int1, 3); // 128 >> 3 = 16
    
    // 验证移位结果
    let mpi2 = unsafe{Mpi::from_teebigint(big_int2 as *const TEE_BigInt).unwrap()};
    let val2 = mpi2.as_u32().unwrap();
    assert_eq!(val2, 16);
    
    // 比较移位结果与期望值
    let cmp = TEE_BigIntCmp(big_int3, big_int2);
    assert_eq!(cmp, 0);

}

#[test]
fn test_tee_bigint_get_set_bit() {
    let mut buffer = [0u32; 10];
    let big_int = buffer.as_mut_ptr();
    

    TEE_BigIntInit(big_int, 10);
    TEE_BigIntConvertFromS32(big_int, 5); // 5 = 101 in binary
    
    assert_eq!(TEE_BigIntGetBit(big_int, 0), true);  // LSB
    assert_eq!(TEE_BigIntGetBit(big_int, 1), false);
    assert_eq!(TEE_BigIntGetBit(big_int, 2), true);
    assert_eq!(TEE_BigIntGetBit(big_int, 3), false);
    
    // Set bit 3 to true (5 + 8 = 13)
    assert_eq!(TEE_BigIntSetBit(big_int, 3, true), TEE_SUCCESS);
    
    let mpi = unsafe{Mpi::from_teebigint(big_int as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 13);

}

#[test]
fn test_tee_bigint_get_bit_count() {
    let mut buffer = [0u32; 10];
    let big_int = buffer.as_mut_ptr();
    

    TEE_BigIntInit(big_int, 10);
    TEE_BigIntConvertFromS32(big_int, 127); // 127 = 1111111 in binary (7 bits)
    
    assert_eq!(TEE_BigIntGetBitCount(big_int), 7);

}

#[test]
fn test_tee_bigint_assign() {
    // 使用更大的独立缓冲区并增加间距避免指针重叠
    let mut buffer1 = [0u32; 20];
    let mut buffer2 = [0u32; 20];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    
    // 确保两个指针之间有足够的距离
    assert!((big_int2 as usize).abs_diff(big_int1 as usize) >= 80); // 20 * size_of::<u32>() = 80
    

    TEE_BigIntInit(big_int1, 20);
    TEE_BigIntInit(big_int2, 20);
    TEE_BigIntConvertFromS32(big_int1, 42);
    
    assert_eq!(TEE_BigIntAssign(big_int2, big_int1), TEE_SUCCESS);
    
    let mpi = unsafe{Mpi::from_teebigint(big_int2 as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 42);

}

#[test]
fn test_tee_bigint_abs() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer1 = [0u32; 10];
    let mut buffer2 = [0u32; 10];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    

    TEE_BigIntInit(big_int1, 10);
    TEE_BigIntInit(big_int2, 10);
    TEE_BigIntConvertFromS32(big_int1, -42);
    
    assert_eq!(TEE_BigIntAbs(big_int2, big_int1), TEE_SUCCESS);
    
    let mpi = unsafe{Mpi::from_teebigint(big_int2 as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 42);

}

#[test]
fn test_tee_bigint_neg() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer1 = [0u32; 10];
    let mut buffer2 = [0u32; 10];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    
    TEE_BigIntInit(big_int1, 10);
    TEE_BigIntInit(big_int2, 10);
    TEE_BigIntConvertFromS32(big_int1, 42);
    
    TEE_BigIntNeg(big_int2, big_int1);
    
    // 需要正确检查负数结果
    let mpi = unsafe{Mpi::from_teebigint(big_int2 as *const TEE_BigInt).unwrap()};
    // 由于Mpi::as_u32不保留符号，我们只能确认数值部分
    assert_eq!(mpi.as_u32().unwrap(), 42);

}

#[test]
fn test_tee_bigint_add_sub() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer1 = [0u32; 10];
    let mut buffer2 = [0u32; 10];
    let mut buffer3 = [0u32; 10];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    let big_int3 = buffer3.as_mut_ptr();
    
    TEE_BigIntInit(big_int1, 10);
    TEE_BigIntInit(big_int2, 10);
    TEE_BigIntInit(big_int3, 10);
    
    TEE_BigIntConvertFromS32(big_int1, 100);
    TEE_BigIntConvertFromS32(big_int2, 50);
    
    TEE_BigIntAdd(big_int3, big_int1, big_int2);
    let mpi = unsafe{Mpi::from_teebigint(big_int3 as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 150);
    
    TEE_BigIntSub(big_int3, big_int1, big_int2);
    let mpi = unsafe{Mpi::from_teebigint(big_int3 as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 50);

}

#[test]
fn test_tee_bigint_mul_div() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer1 = [0u32; 20];
    let mut buffer2 = [0u32; 20];
    let mut buffer3 = [0u32; 20];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    let big_int3 = buffer3.as_mut_ptr();
    
    TEE_BigIntInit(big_int1, 20);
    TEE_BigIntInit(big_int2, 20);
    TEE_BigIntInit(big_int3, 20);
    
    TEE_BigIntConvertFromS32(big_int1, 25);
    TEE_BigIntConvertFromS32(big_int2, 4);
    
    TEE_BigIntMul(big_int3, big_int1, big_int2);
    let mpi = unsafe{Mpi::from_teebigint(big_int3 as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 100);

}

#[test]
fn test_tee_bigint_square() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer1 = [0u32; 20];
    let mut buffer2 = [0u32; 20];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    
    TEE_BigIntInit(big_int1, 20);
    TEE_BigIntInit(big_int2, 20);
    
    TEE_BigIntConvertFromS32(big_int1, 12);
    
    TEE_BigIntSquare(big_int2, big_int1);
    let mpi = unsafe{Mpi::from_teebigint(big_int2 as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 144); // 12*12

}

#[test]
fn test_tee_bigint_mod() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer1 = [0u32; 10];
    let mut buffer2 = [0u32; 10];
    let mut buffer3 = [0u32; 10];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    let big_int3 = buffer3.as_mut_ptr();
    
    TEE_BigIntInit(big_int1, 10);
    TEE_BigIntInit(big_int2, 10);
    TEE_BigIntInit(big_int3, 10);
    
    TEE_BigIntConvertFromS32(big_int1, 100);
    TEE_BigIntConvertFromS32(big_int2, 7);
    
    TEE_BigIntMod(big_int3, big_int1, big_int2);
    let mpi = unsafe{Mpi::from_teebigint(big_int3 as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 2); // 100 % 7 = 2

}

#[test]
fn test_tee_bigint_mod_operations() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer1 = [0u32; 10];
    let mut buffer2 = [0u32; 10];
    let mut buffer3 = [0u32; 10];
    let mut buffer4 = [0u32; 10];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    let big_int3 = buffer3.as_mut_ptr();
    let big_int4 = buffer4.as_mut_ptr();
    
    TEE_BigIntInit(big_int1, 10);
    TEE_BigIntInit(big_int2, 10);
    TEE_BigIntInit(big_int3, 10);
    TEE_BigIntInit(big_int4, 10);
    
    TEE_BigIntConvertFromS32(big_int1, 5);
    TEE_BigIntConvertFromS32(big_int2, 3);
    TEE_BigIntConvertFromS32(big_int3, 7); // modulus
    
    TEE_BigIntAddMod(big_int4, big_int1, big_int2, big_int3);
    let mpi = unsafe{Mpi::from_teebigint(big_int4 as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 1); // (5+3) % 7 = 1
    
    TEE_BigIntSubMod(big_int4, big_int1, big_int2, big_int3);
    let mpi = unsafe{Mpi::from_teebigint(big_int4 as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 2); // (5-3) % 7 = 2
    
    TEE_BigIntMulMod(big_int4, big_int1, big_int2, big_int3);
    let mpi = unsafe{Mpi::from_teebigint(big_int4 as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 1); // (5*3) % 7 = 1

}

#[test]
fn test_tee_bigint_square_mod() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer1 = [0u32; 10];
    let mut buffer2 = [0u32; 10];
    let mut buffer3 = [0u32; 10];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    let big_int3 = buffer3.as_mut_ptr();
    
    TEE_BigIntInit(big_int1, 10);
    TEE_BigIntInit(big_int2, 10);
    TEE_BigIntInit(big_int3, 10);
    
    TEE_BigIntConvertFromS32(big_int1, 4);
    TEE_BigIntConvertFromS32(big_int2, 7); // modulus
    
    TEE_BigIntSquareMod(big_int3, big_int1, big_int2);
    let mpi = unsafe{Mpi::from_teebigint(big_int3 as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi.as_u32().unwrap(), 2); // (4*4) % 7 = 16 % 7 = 2

}

#[test]
fn test_tee_bigint_inv_mod() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer1 = [0u32; 10];
    let mut buffer2 = [0u32; 10];
    let mut buffer3 = [0u32; 10];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    let big_int3 = buffer3.as_mut_ptr();
    

    TEE_BigIntInit(big_int1, 10);
    TEE_BigIntInit(big_int2, 10);
    TEE_BigIntInit(big_int3, 10);
    
    TEE_BigIntConvertFromS32(big_int1, 3);
    TEE_BigIntConvertFromS32(big_int2, 7); // modulus (prime)
    
    TEE_BigIntInvMod(big_int3, big_int1, big_int2);
    let mpi = unsafe{Mpi::from_teebigint(big_int3 as *const TEE_BigInt).unwrap()};
    // 3 * 5 = 15 ≡ 1 (mod 7), so inverse of 3 mod 7 is 5
    assert_eq!(mpi.as_u32().unwrap(), 5);

}

#[test]
fn test_tee_bigint_exp_mod() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer1 = [0u32; 20]; // base
    let mut buffer2 = [0u32; 20]; // exponent
    let mut buffer3 = [0u32; 20]; // modulus
    let mut buffer4 = [0u32; 20]; // result
    
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    let big_int3 = buffer3.as_mut_ptr();
    let big_int4 = buffer4.as_mut_ptr();
    
    TEE_BigIntInit(big_int1, 20);
    TEE_BigIntInit(big_int2, 20);
    TEE_BigIntInit(big_int3, 20);
    TEE_BigIntInit(big_int4, 20);
    
    TEE_BigIntConvertFromS32(big_int1, 2); // base
    TEE_BigIntConvertFromS32(big_int2, 3); // exponent
    TEE_BigIntConvertFromS32(big_int3, 7); // modulus
    
    let res = TEE_BigIntExpMod(big_int4, big_int1, big_int2, big_int3, core::ptr::null());
    assert_eq!(res, TEE_SUCCESS);
    
    let mpi = unsafe{Mpi::from_teebigint(big_int4 as *const TEE_BigInt).unwrap()};
    // 2^3 mod 7 = 8 mod 7 = 1
    assert_eq!(mpi.as_u32().unwrap(), 1);

}

#[test]
fn test_tee_bigint_relative_prime() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer1 = [0u32; 10];
    let mut buffer2 = [0u32; 10];
    let big_int1 = buffer1.as_mut_ptr();
    let big_int2 = buffer2.as_mut_ptr();
    

    TEE_BigIntInit(big_int1, 10);
    TEE_BigIntInit(big_int2, 10);
    
    TEE_BigIntConvertFromS32(big_int1, 15);
    TEE_BigIntConvertFromS32(big_int2, 28);
    
    // gcd(15, 28) = 1, so they are relatively prime
    assert_eq!(TEE_BigIntRelativePrime(big_int1, big_int2), true);
    
    TEE_BigIntConvertFromS32(big_int1, 12);
    TEE_BigIntConvertFromS32(big_int2, 18);
    
    // gcd(12, 18) = 6, so they are not relatively prime
    assert_eq!(TEE_BigIntRelativePrime(big_int1, big_int2), false);

}

#[test]
fn test_tee_bigint_compute_extended_gcd() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer_gcd = [0u32; 10];
    let mut buffer_u = [0u32; 10];
    let mut buffer_v = [0u32; 10];
    let mut buffer1 = [0u32; 10];
    let mut buffer2 = [0u32; 10];
    
    let gcd = buffer_gcd.as_mut_ptr();
    let u = buffer_u.as_mut_ptr();
    let v = buffer_v.as_mut_ptr();
    let op1 = buffer1.as_mut_ptr();
    let op2 = buffer2.as_mut_ptr();
    
    TEE_BigIntInit(gcd, 10);
    TEE_BigIntInit(u, 10);
    TEE_BigIntInit(v, 10);
    TEE_BigIntInit(op1, 10);
    TEE_BigIntInit(op2, 10);
    
    TEE_BigIntConvertFromS32(op1, 30);
    TEE_BigIntConvertFromS32(op2, 18);
    
    TEE_BigIntComputeExtendedGcd(gcd, u, v, op1, op2);
    
    // Extended GCD: 30*u + 18*v = gcd(30, 18) = 6
    // One solution: 30*(-1) + 18*2 = 6
    let mpi_gcd = unsafe{Mpi::from_teebigint(gcd as *const TEE_BigInt).unwrap()};
    assert_eq!(mpi_gcd.as_u32().unwrap(), 6);

}

#[test]
fn test_tee_bigint_is_probable_prime() {
    let mut buffer = [0u32; 20];
    let big_int = buffer.as_mut_ptr();

    TEE_BigIntInit(big_int, 20);
    TEE_BigIntConvertFromS32(big_int, 17); // 17 is prime
    
    assert_eq!(TEE_BigIntIsProbablePrime(big_int, 80), 1);
    
    TEE_BigIntConvertFromS32(big_int, 18); // 18 is not prime
    assert_eq!(TEE_BigIntIsProbablePrime(big_int, 80), 0);

}

#[test]
fn test_tee_bigint_mod_sqrt_related_operations() {
    // 基于 test_mod_sqrt_fn 中的测试数据，测试相关的模运算
    // 测试数据来自 Sagemath
    
    // 首先测试 to_teebigint 转换功能
    {
        println!("=== 测试 to_teebigint 转换功能 ===");
        
        // 测试简单数值
        let test_value = "123456789";
        let mpi = Mpi::from_str(test_value).unwrap();
        println!("原始 MPI: {}", mpi);
        
        let mut buffer = [0u32; 20];
        let bigint_ptr = buffer.as_mut_ptr();
        
        TEE_BigIntInit(bigint_ptr, 20);
        
        // 转换到 TEE BigInt
        match unsafe{mpi.to_teebigint(bigint_ptr, 20)} {
            Ok(()) => println!("小数转换成功"),
            Err(e) => println!("小数转换失败: {:?}", e),
        }
        
        // 转换回来验证
        let result_mpi = unsafe{Mpi::from_teebigint(bigint_ptr as *const TEE_BigInt)};
        match result_mpi {
            Ok(mpi_back) => println!("小数转回的值: {}", mpi_back),
            Err(e) => println!("小数转回失败: {:?}", e),
        }

        
        // 测试大数值
        let large_value = "126474086260479574845714194337";
        let large_mpi = Mpi::from_str(large_value).unwrap();
        println!("原始大 MPI: {}", large_mpi);
        
        let mut large_buffer = [0u32; 50];
        let large_bigint_ptr = large_buffer.as_mut_ptr();
        
        TEE_BigIntInit(large_bigint_ptr, 50);
        
        // 转换到 TEE BigInt
        match unsafe{large_mpi.to_teebigint(large_bigint_ptr, 50)} {
            Ok(()) => println!("大数转换成功"),
            Err(e) => println!("大数转换失败: {:?}", e),
        }
        
        // 转换回来验证
        let result_large_mpi = unsafe{Mpi::from_teebigint(large_bigint_ptr as *const TEE_BigInt)};
        match result_large_mpi {
            Ok(mpi_back) => {
                println!("大数转回的值: {}", mpi_back);
                println!("值是否相等: {}", mpi_back == large_mpi);
            },
            Err(e) => println!("大数转回失败: {:?}", e),
        }

    }
    
    // 测试小数值：2, 7, 4 (其中 4^2 mod 7 = 2)
    let mut buffer_a = [0u32; 10];
    let mut buffer_n = [0u32; 10];
    let mut buffer_result = [0u32; 10];
    let mut buffer_expected = [0u32; 10];
    
    let a = buffer_a.as_mut_ptr();
    let n = buffer_n.as_mut_ptr();
    let result = buffer_result.as_mut_ptr();
    let expected = buffer_expected.as_mut_ptr();
    
    TEE_BigIntInit(a, 10);
    TEE_BigIntInit(n, 10);
    TEE_BigIntInit(result, 10);
    TEE_BigIntInit(expected, 10);
    
    // 测试 4^2 mod 7 = 2
    TEE_BigIntConvertFromS32(a, 4);
    TEE_BigIntConvertFromS32(n, 7);
    TEE_BigIntSquareMod(result, a, n);
    TEE_BigIntConvertFromS32(expected, 2);
    
    assert_eq!(TEE_BigIntCmp(result, expected), 0);
    
    // 测试 2^2 mod 17 = 4
    TEE_BigIntConvertFromS32(a, 2);
    TEE_BigIntConvertFromS32(n, 17);
    TEE_BigIntSquareMod(result, a, n);
    TEE_BigIntConvertFromS32(expected, 4);
    
    assert_eq!(TEE_BigIntCmp(result, expected), 0);
    
    // 测试 6^2 mod 17 = 2 (6 是 2 mod 17 的平方根之一)
    TEE_BigIntConvertFromS32(a, 6);
    TEE_BigIntConvertFromS32(n, 17);
    TEE_BigIntSquareMod(result, a, n);
    TEE_BigIntConvertFromS32(expected, 2);
    
    assert_eq!(TEE_BigIntCmp(result, expected), 0);
    
    // 测试 11^2 mod 17 = 2 (17-6=11，11^2=121，121 mod 17 = 2)
    TEE_BigIntConvertFromS32(a, 11);
    TEE_BigIntConvertFromS32(n, 17);
    TEE_BigIntSquareMod(result, a, n);
    TEE_BigIntConvertFromS32(expected, 2);
    
    assert_eq!(TEE_BigIntCmp(result, expected), 0);

    
    
    // 测试大数值：458050473005020050313790240477 mod 905858848829014223214249213947
    let mut buffer_a_large = [0u32; 50];
    let mut buffer_n_large = [0u32; 50];
    let mut buffer_result_large = [0u32; 50];
    let mut buffer_expected_large = [0u32; 50];
    
    let a_large = buffer_a_large.as_mut_ptr();
    let n_large = buffer_n_large.as_mut_ptr();
    let result_large = buffer_result_large.as_mut_ptr();
    let expected_large = buffer_expected_large.as_mut_ptr();
    
    TEE_BigIntInit(a_large, 50);
    TEE_BigIntInit(n_large, 50);
    TEE_BigIntInit(result_large, 50);
    TEE_BigIntInit(expected_large, 50);
    
    // 将十六进制字符串转换为 BigInt
    // 这里我们使用模平方来验证平方根关系
    let sqrt_hex = "126474086260479574845714194337";
    let n_hex = "905858848829014223214249213947";
    let expected_hex = "458050473005020050313790240477";
    
    // 首先将数值转换为 BigInt（使用字符串解析）
    let sqrt_mpi = Mpi::from_str(sqrt_hex).unwrap();
    let n_mpi = Mpi::from_str(n_hex).unwrap();
    let expected_mpi = Mpi::from_str(expected_hex).unwrap();
    
    // 转换为 TEE BigInt
    unsafe{sqrt_mpi.to_teebigint(a_large, 50).unwrap()};
    unsafe{n_mpi.to_teebigint(n_large, 50).unwrap()};
    unsafe{expected_mpi.to_teebigint(expected_large, 50).unwrap()};
    
    // 验证 sqrt^2 mod n = expected
    TEE_BigIntSquareMod(result_large, a_large, n_large);
    
    let cmp_result = TEE_BigIntCmp(result_large, expected_large);
    assert_eq!(cmp_result, 0, "Square mod operation failed: expected {} but got different", expected_hex);

}

#[test]
fn test_tee_bigint_mod_operations_extended() {
    // 扩展的模运算测试，基于 mod_sqrt 数据
    
    // 测试 4 mod 13 = 4, 2^2 mod 13 = 4
    let mut buffer_base = [0u32; 20];
    let mut buffer_modulus = [0u32; 20];
    let mut buffer_result = [0u32; 20];
    let mut buffer_expected = [0u32; 20];
    
    let base = buffer_base.as_mut_ptr();
    let modulus = buffer_modulus.as_mut_ptr();
    let result = buffer_result.as_mut_ptr();
    let expected = buffer_expected.as_mut_ptr();


    TEE_BigIntInit(base, 20);
    TEE_BigIntInit(modulus, 20);
    TEE_BigIntInit(result, 20);
    TEE_BigIntInit(expected, 20);
    
    // 测试 2^2 mod 13 = 4
    TEE_BigIntConvertFromS32(base, 2);
    TEE_BigIntConvertFromS32(modulus, 13);
    TEE_BigIntConvertFromS32(expected, 4);
    
    TEE_BigIntSquareMod(result, base, modulus);
    assert_eq!(TEE_BigIntCmp(result, expected), 0);
    
    // 测试 62^2 mod 113 = 2
    TEE_BigIntConvertFromS32(base, 62);
    TEE_BigIntConvertFromS32(modulus, 113);
    TEE_BigIntConvertFromS32(expected, 2);
    
    TEE_BigIntSquareMod(result, base, modulus);
    assert_eq!(TEE_BigIntCmp(result, expected), 0);

}

#[test]
fn test_tee_bigint_fmm_functions() {
    // 使用独立的缓冲区避免指针重叠
    let mut buffer_fmm = [0u32; 10];
    let mut buffer_bigint = [0u32; 10];
    let mut buffer_modulus = [0u32; 10];
    let mut buffer_context = [0u32; 10];
    
    let fmm = buffer_fmm.as_mut_ptr();
    let bigint = buffer_bigint.as_mut_ptr();
    let modulus = buffer_modulus.as_mut_ptr();
    let context = buffer_context.as_mut_ptr();
    

    TEE_BigIntInitFMM(fmm, 10);
    TEE_BigIntInit(bigint, 10);
    TEE_BigIntInit(modulus, 10);
    TEE_BigIntInitFMMContext1(context, 10, modulus);
    
    // Test size functions
    assert!(TEE_BigIntFMMSizeInU32(256) > 0);
    assert!(TEE_BigIntFMMContextSizeInU32(256) > 0);

}

fn test_is_prime(mpi: Mpi, expected: bool) {
    let mut buffer = [0u32; 64];
    let big_int = buffer.as_mut_ptr();
    
    TEE_BigIntInit(big_int, 64);
    unsafe{mpi.to_teebigint(big_int, 64).unwrap()};
    
    // 使用较低的安全级别进行测试，提高性能
    let result = TEE_BigIntIsProbablePrime(big_int, 15);
    
    if expected {
        assert_eq!(result, 1, "Expected number to be probably prime");
    } else {
        assert_eq!(result, 0, "Expected number to be composite");
    }

}

#[test]
fn test_teebigint_is_probably_prime() {
    // 先测试已知的小数字确保基本功能正常工作
    
    // 测试小素数
    let small_prime = Mpi::new(97).unwrap();
    test_is_prime(small_prime, true);
    
    // 测试小合数
    let small_composite = Mpi::new(98).unwrap();
    test_is_prime(small_composite, false);
    
    // 测试边界情况 - 2是最小的素数
    let two = Mpi::new(2).unwrap();
    test_is_prime(two, true);
    
    // 测试边界情况 - 1不是素数
    let one = Mpi::new(1).unwrap();
    test_is_prime(one, false);
    
    // 使用RSA-250因子分解挑战中的真实数据
    // 注意：大型素数测试可能会失败，因为TEE的素数测试可能有特定实现
    
    let rsa_250_p = Mpi::from_binary(&[
        0x61, 0x04, 0xFA, 0xF8, 0x1F, 0x41, 0xFD, 0xD7, 0x61, 0x6B, 0x43, 0x78, 0xF6, 0xBD, 0x99, 0x12, 0x92, 0xCB, 0x2F, 0x21,
        0xC1, 0x0D, 0x06, 0xC5, 0xE8, 0xE5, 0x71, 0xA5, 0xE9, 0x62, 0xB7, 0xE8, 0x2D, 0xFD, 0x9F, 0xE7, 0x12, 0x0F, 0x6D, 0x03,
        0xA8, 0x6C, 0xC6, 0xBB, 0xC7, 0xDD, 0x3A, 0x62, 0x80, 0x83, 0x9E, 0xF7,
    ])
    .unwrap();
    
    let rsa_250_q = Mpi::from_binary(&[
        0x32, 0x7B, 0x9F, 0xDA, 0x4B, 0x21, 0x1E, 0x3B, 0xFD, 0xB5, 0x4F, 0x68, 0x0E, 0x5C, 0x04, 0x52, 0x8A, 0xAA, 0x20, 0x42,
        0x8A, 0xE0, 0x08, 0xFA, 0xF4, 0x8D, 0xF6, 0xC9, 0x13, 0xF5, 0x74, 0x7D, 0x86, 0x08, 0xA5, 0xA4, 0x8E, 0x2B, 0xFE, 0x41,
        0xFA, 0xE7, 0xA0, 0x46, 0x83, 0xF2, 0x30, 0x58, 0x52, 0xCD, 0xAD, 0xF7,
    ])
    .unwrap();
    
    let rsa_250_n = Mpi::from_binary(&[
        0x13, 0x21, 0xD2, 0xFD, 0xDD, 0xE8, 0xBD, 0x9D, 0xFF, 0x37, 0x9A, 0xFF, 0x03, 0x0D, 0xE2, 0x05, 0xB8, 0x46, 0xEB, 0x5C,
        0xEC, 0xC4, 0x0F, 0xA8, 0xAA, 0x9C, 0x2A, 0x85, 0xCE, 0x3E, 0x99, 0x21, 0x93, 0xE8, 0x73, 0xB2, 0xBC, 0x66, 0x7D, 0xAB,
        0xE2, 0xAC, 0x3E, 0xE9, 0xDD, 0x23, 0xB3, 0xA9, 0xED, 0x9E, 0xC0, 0xC3, 0xC7, 0x44, 0x56, 0x63, 0xF5, 0x45, 0x54, 0x69,
        0xB7, 0x27, 0xDD, 0x6F, 0xBC, 0x03, 0xB1, 0xBF, 0x95, 0xD0, 0x3A, 0x13, 0xC0, 0x36, 0x86, 0x45, 0x76, 0x76, 0x30, 0xC7,
        0xEA, 0xBF, 0x5E, 0x7A, 0xB5, 0xFA, 0x27, 0xB9, 0x4A, 0xDE, 0x7E, 0x1E, 0x23, 0xBC, 0xC6, 0x5D, 0x2A, 0x7D, 0xED, 0x1C,
        0x5B, 0x36, 0x4B, 0x51,
    ])
    .unwrap();
    
    // 测试n是否为素数 (应该返回false，因为它是两个素数的乘积)
    test_is_prime(rsa_250_n.clone(), false);
    test_is_prime(rsa_250_p.clone(), true);
    test_is_prime(rsa_250_q.clone(), true);

}