use core::arch::asm;

pub type syscall_num = usize;

#[inline(always)]
pub unsafe fn syscall0(n: syscall_num) -> usize {
    let ret: usize;
    unsafe {
        asm!("svc #0", in("x8") n + 500, lateout("x0") ret, options(nostack));
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall1(n: syscall_num, arg0: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!("svc #0", in("x8") n + 500, in("x0") arg0, lateout("x0") ret, options(nostack));
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall2(n: syscall_num, arg0: usize, arg1: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n + 500,
            in("x0") arg0,
            in("x1") arg1,
            lateout("x0") ret,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall3(n: syscall_num, arg0: usize, arg1: usize, arg2: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n + 500,
            in("x0") arg0,
            in("x1") arg1,
            in("x2") arg2,
            lateout("x0") ret,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall4(
    n: syscall_num,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n + 500,
            in("x0") arg0,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            lateout("x0") ret,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall5(
    n: syscall_num,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n + 500,
            in("x0") arg0,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            lateout("x0") ret,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall6(
    n: syscall_num,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n + 500,
            in("x0") arg0,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            in("x5") arg5,
            lateout("x0") ret,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall7(
    n: syscall_num,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n + 500,
            in("x0") arg0,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            in("x5") arg5,
            in("x6") arg6,
            lateout("x0") ret,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall8(
    n: syscall_num,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
    arg7: usize,
) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n + 500,
            in("x0") arg0,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            in("x5") arg5,
            in("x6") arg6,
            in("x7") arg7,
            lateout("x0") ret,
        );
    }
    ret
}
