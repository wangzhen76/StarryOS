use rust_utee::api::tee_api_cancel::{
    TEE_GetCancellationFlag, TEE_MaskCancellation, TEE_UnmaskCancellation,
};

// #[unsafe(no_mangle)]
fn main() {
    let flag = TEE_GetCancellationFlag();
    println!("flag: {}", flag);
    println!("first mask cancel");
    TEE_MaskCancellation();
    let flag = TEE_GetCancellationFlag();
    println!("flag: {}", flag);
    TEE_UnmaskCancellation();
    let flag = TEE_GetCancellationFlag();
    println!("flag: {}", flag);
}
