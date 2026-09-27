//! Raw trap instructions used by the generated `user` syscalls.
//!
//! The kernel's entry code must honor the calling convention for the given architecture:
//!
//! | arch    | trap      | nr  | args                   | return | clobbered by the trap |
//! |---------|-----------|-----|------------------------|--------|-----------------------|
//! | x86_64  | `syscall` | rax | rdi rsi rdx r10 r8 r9  | rax    | rcx, r11, flags       |
//! | aarch64 | `svc #0`  | x8  | x0 x1 x2 x3 x4 x5      | x0     | flags                 |
//! | riscv64 | `ecall`   | a7  | a0 a1 a2 a3 a4 a5      | a0     | none                  |

#[cfg(all(
    feature = "user",
    not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))
))]
compile_error!("sysabi: `user` feature is only supported on x86_64, aarch64, and riscv64");

#[cfg(target_arch = "x86_64")]
macro_rules! syscall_fns {
    ($($name:ident($($a:ident: $reg:tt),*);)*) => {$(
        /// # Safety
        /// Performs an arbitrary syscall. The caller needs to uphold whatever the
        /// kernel requires of `nr` and the arguments.
        #[inline(always)]
        pub unsafe fn $name(nr: usize, $($a: usize),*) -> usize {
            let ret;

            unsafe {
                core::arch::asm!(
                    "syscall",
                    inlateout("rax") nr => ret,
                    $(in($reg) $a,)*
                    lateout("rcx") _,
                    lateout("r11") _,
                    options(nostack),
                );
            }

            ret
        }
    )*};
}

#[cfg(target_arch = "aarch64")]
macro_rules! syscall_fns {
    ($($name:ident($($a:ident: $reg:tt),*);)*) => {$(
        /// # Safety
        /// Performs an arbitrary syscall. The caller needs to uphold whatever the
        /// kernel requires of `nr` and the arguments.
        #[inline(always)]
        pub unsafe fn $name(nr: usize, $($a: usize),*) -> usize {
            let ret;

            unsafe {
                syscall_fns!(@asm "svc #0", "x8", "x0", nr, ret; $($a: $reg),*);
            }

            ret
        }
    )*};

    (@asm $insn:tt, $nr:tt, $ret:tt, $nrv:ident, $retv:ident; $a0:ident: $r0:tt $(, $a:ident: $reg:tt)*) => {
        core::arch::asm!($insn, in($nr) $nrv, inlateout($ret) $a0 => $retv, $(in($reg) $a,)* options(nostack))
    };

    (@asm $insn:tt, $nr:tt, $ret:tt, $nrv:ident, $retv:ident;) => {
        core::arch::asm!($insn, in($nr) $nrv, lateout($ret) $retv, options(nostack))
    };
}

#[cfg(target_arch = "riscv64")]
macro_rules! syscall_fns {
    ($($name:ident($($a:ident: $reg:tt),*);)*) => {$(
        /// # Safety
        /// Performs an arbitrary syscall. The caller needs to uphold whatever the
        /// kernel requires of `nr` and the arguments.
        #[inline(always)]
        pub unsafe fn $name(nr: usize, $($a: usize),*) -> usize {
            let ret;

            unsafe {
                syscall_fns!(@asm "ecall", "a7", "a0", nr, ret; $($a: $reg),*);
            }

            ret
        }
    )*};

    (@asm $insn:tt, $nr:tt, $ret:tt, $nrv:ident, $retv:ident; $a0:ident: $r0:tt $(, $a:ident: $reg:tt)*) => {
        core::arch::asm!($insn, in($nr) $nrv, inlateout($ret) $a0 => $retv, $(in($reg) $a,)* options(nostack, preserves_flags))
    };

    (@asm $insn:tt, $nr:tt, $ret:tt, $nrv:ident, $retv:ident;) => {
        core::arch::asm!($insn, in($nr) $nrv, lateout($ret) $retv, options(nostack, preserves_flags))
    };
}

#[cfg(target_arch = "x86_64")]
syscall_fns! {
    syscall0();
    syscall1(a0: "rdi");
    syscall2(a0: "rdi", a1: "rsi");
    syscall3(a0: "rdi", a1: "rsi", a2: "rdx");
    syscall4(a0: "rdi", a1: "rsi", a2: "rdx", a3: "r10");
    syscall5(a0: "rdi", a1: "rsi", a2: "rdx", a3: "r10", a4: "r8");
    syscall6(a0: "rdi", a1: "rsi", a2: "rdx", a3: "r10", a4: "r8", a5: "r9");
}

#[cfg(target_arch = "aarch64")]
syscall_fns! {
    syscall0();
    syscall1(a0: "x0");
    syscall2(a0: "x0", a1: "x1");
    syscall3(a0: "x0", a1: "x1", a2: "x2");
    syscall4(a0: "x0", a1: "x1", a2: "x2", a3: "x3");
    syscall5(a0: "x0", a1: "x1", a2: "x2", a3: "x3", a4: "x4");
    syscall6(a0: "x0", a1: "x1", a2: "x2", a3: "x3", a4: "x4", a5: "x5");
}

#[cfg(target_arch = "riscv64")]
syscall_fns! {
    syscall0();
    syscall1(a0: "a0");
    syscall2(a0: "a0", a1: "a1");
    syscall3(a0: "a0", a1: "a1", a2: "a2");
    syscall4(a0: "a0", a1: "a1", a2: "a2", a3: "a3");
    syscall5(a0: "a0", a1: "a1", a2: "a2", a3: "a3", a4: "a4");
    syscall6(a0: "a0", a1: "a1", a2: "a2", a3: "a3", a4: "a4", a5: "a5");
}
