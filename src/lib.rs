// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.
//
// This file has been modified by KylinSoft on 2025.

#![allow(non_camel_case_types, non_snake_case)]

pub mod tee_api_arith_mpi;
pub mod tee_api_defines;
pub mod tee_api_mm;
pub mod tee_api_panic;
pub mod tee_api_types;

mod libc_compat {
    pub type size_t = usize;
    pub type intmax_t = i64;
}
