#[macro_export]
macro_rules! define_utee_syscalls {

    ( $( $id_name:ident = $id_val:expr => fn $func_name:ident() );* $(;)? ) => {
        $(
            pub const $id_name: usize = $id_val;

            #[inline]
            pub unsafe extern "C" fn $func_name() -> usize {
                unsafe {
                    $crate::syscalls::raw_syscall::syscall0($id_name)
                }
            }
        )*
    };

    ( $( $id_name:ident = $id_val:expr => fn $func_name:ident($a:ident : $at:ty) );* $(;)? ) => {
        $(
            pub const $id_name: usize = $id_val;

            #[inline]
            pub unsafe extern "C" fn $func_name($a: $at) -> usize {
                unsafe {
                    $crate::syscalls::raw_syscall::syscall1($id_name, $a as usize)
                }
            }
        )*
    };

    ( $( $id_name:ident = $id_val:expr => fn $func_name:ident($a:ident : $at:ty, $b:ident : $bt:ty) );* $(;)? ) => {
        $(
            pub const $id_name: usize = $id_val;

            #[inline]
            pub unsafe extern "C" fn $func_name($a: $at, $b: $bt) -> usize {
                unsafe {
                    $crate::syscalls::raw_syscall::syscall2($id_name, $a as usize, $b as usize)
                }
            }
        )*
    };


    ( $( $id_name:ident = $id_val:expr => fn $func_name:ident($a:ident : $at:ty, $b:ident : $bt:ty, $c:ident : $ct:ty) );* $(;)? ) => {
        $(
            pub const $id_name: usize = $id_val;

            #[inline]
            pub unsafe extern "C" fn $func_name($a: $at, $b: $bt, $c: $ct) -> usize {
                unsafe {
                    $crate::syscalls::raw_syscall::syscall3($id_name, $a as usize, $b as usize, $c as usize)
                }
            }
        )*
    };

    ( $( $id_name:ident = $id_val:expr => fn $func_name:ident($a:ident : $at:ty, $b:ident : $bt:ty, $c:ident : $ct:ty, $d:ident : $dt:ty) );* $(;)? ) => {
        $(
            pub const $id_name: usize = $id_val;
            #[inline]
            pub unsafe extern "C" fn $func_name($a: $at, $b: $bt, $c: $ct, $d: $dt) -> usize {
                unsafe {
                    $crate::syscalls::raw_syscall::syscall4($id_name, $a as usize, $b as usize, $c as usize, $d as usize)
                }
            }
        )*
    };

    ( $( $id_name:ident = $id_val:expr => fn $func_name:ident($a:ident : $at:ty, $b:ident : $bt:ty, $c:ident : $ct:ty, $d:ident : $dt:ty, $e:ident : $et:ty) );* $(;)? ) => {
        $(
            pub const $id_name: usize = $id_val;
            #[inline]
            pub unsafe extern "C" fn $func_name($a: $at, $b: $bt, $c: $ct, $d: $dt, $e: $et) -> usize {
                unsafe {
                    $crate::syscalls::raw_syscall::syscall5($id_name, $a as usize, $b as usize, $c as usize, $d as usize, $e as usize)
                }
            }
        )*
    };

    ( $( $id_name:ident = $id_val:expr => fn $func_name:ident($a:ident : $at:ty, $b:ident : $bt:ty, $c:ident : $ct:ty, $d:ident : $dt:ty, $e:ident : $et:ty, $f:ident : $ft:ty) );* $(;)? ) => {
        $(
            pub const $id_name: usize = $id_val;
            #[inline]
            pub unsafe extern "C" fn $func_name($a: $at, $b: $bt, $c: $ct, $d: $dt, $e: $et, $f: $ft) -> usize {
                unsafe {
                    $crate::syscalls::raw_syscall::syscall6($id_name, $a as usize, $b as usize, $c as usize, $d as usize, $e as usize, $f as usize)
                }
            }
        )*
    };

    ( $( $id_name:ident = $id_val:expr => fn $func_name:ident($a:ident : $at:ty, $b:ident : $bt:ty, $c:ident : $ct:ty, $d:ident : $dt:ty, $e:ident : $et:ty, $f:ident : $ft:ty, $g:ident : $gt:ty) );* $(;)? ) => {
        $(
            pub const $id_name: usize = $id_val;
            #[inline]
            pub unsafe extern "C" fn $func_name($a: $at, $b: $bt, $c: $ct, $d: $dt, $e: $et, $f: $ft, $g: $gt) -> usize {
                unsafe {
                    $crate::syscalls::raw_syscall::syscall7($id_name, $a as usize, $b as usize, $c as usize, $d as usize, $e as usize, $f as usize, $g as usize)
                }
            }
        )*
    };

    ( $( $id_name:ident = $id_val:expr => fn $func_name:ident($a:ident : $at:ty, $b:ident : $bt:ty, $c:ident : $ct:ty, $d:ident : $dt:ty, $e:ident : $et:ty, $f:ident : $ft:ty, $g:ident : $gt:ty, $h:ident : $ht:ty) );* $(;)? ) => {
        $(
            pub const $id_name: usize = $id_val;
            #[inline]
            pub unsafe extern "C" fn $func_name($a: $at, $b: $bt, $c: $ct, $d: $dt, $e: $et, $f: $ft, $g: $gt, $h: $ht) -> usize {
                unsafe {
                    $crate::syscalls::raw_syscall::syscall8($id_name, $a as usize, $b as usize, $c as usize, $d as usize, $e as usize, $f as usize, $g as usize, $h as usize)
                }
            }
        )*
    };
}
