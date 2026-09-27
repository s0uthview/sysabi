//! Define a syscall ABI once and generate both halves of it from the same source.
//!
//! ```ignore
//! #[syscall::abi(
//!     abi = "example",
//!     version = 2,
//!     errno = Errno,
//! )]
//! pub trait Demo {
//!     /// Terminate the calling thread.
//!     #[syscall(nr = 0)]
//!     fn exit(code: i32) -> !;
//!
//!     #[syscall(nr = 1)]
//!     unsafe fn write(fd: u32, buf: *const u8, len: usize) -> usize;
//!
//!     #[syscall(nr = 2, since = 2)]
//!     fn getpid() -> u32;
//! }
//! ```
//!
//! Generated in a module named after the trait (`demo` or `module = ...`):
//! - `demo::ABI`: an [`AbiDesc`] with the name + version
//! - `demo::nr::WRITE`, ...: syscall numbers
//! - `demo::SYSCALLS`: [`SyscallDesc`] per syscall
//!
//! `kernel` feature:
//! - `trait Demo` is rewritten into the handler trait implemented by the kernel:
//!   `fn write(&self, cx: &mut Self::Context, fd: u32, buf: *const u8, len: usize) -> Result<usize, Errno>`
//! - `demo::kernel::dispatch(&handler, &hooks, cx, nr, args) -> usize` decodes a trap, runs
//!   [`Hooks::filter`], calls handler, runs [`Hooks::on_return`], encodes the result
//!
//! `user` feature:
//! - `demo::user::write(fd, buf, len) -> Result<usize, Errno>` and other syscalls, which trap into the kernel
//!   with the calling convention in [`arch`], and syscalls declared `unsafe fn` get `unsafe` stubs. The rest
//!   are safe.
//!
//! Both features can be enabled simultaneously, for example in a full kernel + userspace environment.
//!
//! # Return values
//!
//! The return type written in the definition is on success; errors are always the ABI's given `Errno` type.
//! `-> !` becomes `Result<Infallible, Errno>`, and a missing return type becomes `()`.
//!
//! On the wire, results use Linux conventions: success values returned as-is, errors returned as `-code`, with
//! codes in `1..=MAX_ERRNO`.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

extern crate self as sysabi;

pub mod arch;

pub use sysabi_macros::abi;

use core::{convert::Infallible, fmt};

/// The largest valid error code that can be returned.
///
/// Raw returns in `(-MAX_ERRNO as usize)..=usize::MAX` are errors.
pub const MAX_ERRNO: u16 = 4095;

/// The most arguments a syscall can have.
pub const MAX_ARGS: usize = 6;

/// An ABI's error type.
pub trait ErrorCode: Copy {
    /// Returned for a syscall number the ABI does not recognize.
    const NOSYS: Self;
    /// Returned if an argument fails [`SyscallArg::from_raw`].
    const INVAL: Self;

    /// The wire representation of this error code. Must be in `1..=MAX_ERRNO`.
    fn to_code(self) -> u16;

    /// Constructs an error code from its wire representation. Must be in `1..=MAX_ERRNO`.
    fn from_code(code: u16) -> Self;
}

/// A type that can be passed as a syscall argument.
///
/// Implement this trait for argument types (file descriptors, flag sets, pointers, etc.)
/// so they can appear as arguments in syscall definitions.
pub trait SyscallArg: Sized {
    /// Converts the argument into its raw wire representation.
    fn into_raw(self) -> usize;

    /// Constructs the argument from its raw wire representation, or returns `None` if invalid.
    fn from_raw(raw: usize) -> Option<Self>;
}

macro_rules! unsigned_arg {
    ($($t:ty),*) => {$(
        impl SyscallArg for $t {
            #[inline]
            fn into_raw(self) -> usize {
                self as usize
            }

            fn from_raw(raw: usize) -> Option<Self> {
                <$t>::try_from(raw).ok()
            }
        }
    )*};
}

macro_rules! signed_arg {
    ($($t:ty),*) => {$(
        impl SyscallArg for $t {
            #[inline]
            fn into_raw(self) -> usize {
                self as isize as usize
            }

            #[inline]
            fn from_raw(raw: usize) -> Option<Self> {
                <$t>::try_from(raw as isize).ok()
            }
        }
    )*};
}

unsigned_arg!(u8, u16, u32, usize);
#[cfg(target_pointer_width = "64")]
unsigned_arg!(u64);

signed_arg!(i8, i16, i32, isize);
#[cfg(target_pointer_width = "64")]
signed_arg!(i64);

impl SyscallArg for bool {
    #[inline]
    fn into_raw(self) -> usize {
        self as usize
    }

    #[inline]
    fn from_raw(raw: usize) -> Option<Self> {
        match raw {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
}

impl SyscallArg for () {
    #[inline]
    fn into_raw(self) -> usize {
        0
    }

    #[inline]
    fn from_raw(_raw: usize) -> Option<Self> {
        Some(())
    }
}

impl SyscallArg for Infallible {
    fn into_raw(self) -> usize {
        match self {}
    }

    fn from_raw(_raw: usize) -> Option<Self> {
        None
    }
}

impl<T> SyscallArg for *const T {
    #[inline]
    fn into_raw(self) -> usize {
        self as usize
    }

    #[inline]
    fn from_raw(raw: usize) -> Option<Self> {
        Some(raw as *const T)
    }
}

impl<T> SyscallArg for *mut T {
    #[inline]
    fn into_raw(self) -> usize {
        self as usize
    }

    #[inline]
    fn from_raw(raw: usize) -> Option<Self> {
        Some(raw as *mut T)
    }
}

/// Encode a result into a return value.
#[inline]
pub fn encode<E: ErrorCode>(ret: Result<usize, E>) -> usize {
    match ret {
        Ok(v) => {
            debug_assert!(
                decode::<E>(v).is_ok(),
                "success val {v:#x} collides with error range"
            );

            v
        }
        Err(e) => {
            let code = e.to_code();

            debug_assert!(
                (1..=MAX_ERRNO).contains(&code),
                "error code {code} out of range"
            );

            (code as usize).wrapping_neg()
        }
    }
}

/// Decode a return value into a `Result`.
#[inline]
pub fn decode<E: ErrorCode>(raw: usize) -> Result<usize, E> {
    let neg = raw.wrapping_neg();

    if raw != 0 && neg <= MAX_ERRNO as usize {
        Err(E::from_code(neg as u16))
    } else {
        Ok(raw)
    }
}

/// Static description of an ABI.
#[derive(Debug)]
pub struct AbiDesc {
    /// Name of the ABI.
    pub name: &'static str,
    /// Version of the ABI.
    pub version: u32,
}

/// Static description of a syscall.
#[derive(Debug)]
pub struct SyscallDesc {
    /// Name of the syscall.
    pub name: &'static str,
    /// Syscall number.
    pub nr: usize,
    /// Since which version of the ABI the syscall is available.
    pub since: u32,
    /// Description of the syscall arguments.
    pub args: &'static [ArgDesc],
    /// The success type as written in the syscall definition.
    pub ret: &'static str,
    /// Whether the user stub is `unsafe`.
    pub is_unsafe: bool,
}

/// Static description of a syscall argument.
#[derive(Debug)]
pub struct ArgDesc {
    /// Name of the syscall argument.
    pub name: &'static str,
    /// Type of the syscall argument.
    pub ty: &'static str,
}

/// A syscall as seen by [`Hooks`] before its arguments are processed.
///
/// This [`Display`](fmt::Display) implementation prints strace-style lines
/// such as `write(fd=0x1, buf=0x7ffc1000, len=0x5)`.
#[derive(Debug, Clone, Copy)]
pub struct SyscallInfo {
    /// The ABI to which this syscall belongs.
    pub abi: &'static AbiDesc,
    /// The syscall number within the ABI.
    pub nr: usize,
    /// `None` when `nr` is not defined by the ABI. Hooks still run for unknown syscalls,
    /// which then fail with [`ErrorCode::NOSYS`].
    pub desc: Option<&'static SyscallDesc>,
    /// Raw register values.
    pub args: [usize; MAX_ARGS],
}

impl SyscallInfo {
    /// The name of the syscall, if known.
    pub fn name(&self) -> Option<&'static str> {
        self.desc.map(|d| d.name)
    }

    /// The raw values of the arguments this syscall takes.
    ///
    /// All six if unknown.
    pub fn used_args(&self) -> &[usize] {
        let n = self.desc.map_or(MAX_ARGS, |d| d.args.len());

        &self.args[..n]
    }
}

impl fmt::Display for SyscallInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.desc {
            Some(desc) => write!(f, "{}(", desc.name)?,
            None => write!(f, "{}#{}(", self.abi.name, self.nr)?,
        }

        for (i, raw) in self.used_args().iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            if let Some(desc) = self.desc {
                write!(f, "{}=", desc.args[i].name)?;
            }
            write!(f, "{raw:#x}")?;
        }

        f.write_str(")")
    }
}

/// Hooks run by `kernel::dispatch` around a syscall, known or not.
///
/// `Cx` is the handler's `Context` (the calling thread or process) and `E` is
/// the ABI's error type.
///
/// Hooks compose: `()` does nothing, `&H` forwards, `Option<H>` runs when `Some`, and a
/// tuple `(A, B, ...)` runs each filter in order, stopping at the first denial, then runs
/// every `on_return` in reverse order.
pub trait Hooks<Cx: ?Sized, E> {
    /// Called before the arguments of a syscall are processed.
    ///
    /// Returning `Err` skips the handler and fails the syscall with the given error.
    #[inline]
    fn filter(&self, cx: &mut Cx, info: &SyscallInfo) -> Result<(), E> {
        let _ = (cx, info);

        Ok(())
    }

    /// Called with the final result including when the filter denied the syscall,
    /// the syscall was unknown, or an argument failed to decode. `Ok` holds the encoded
    /// success value.
    #[inline]
    fn on_return(&self, cx: &mut Cx, info: &SyscallInfo, ret: &Result<usize, E>) {
        let _ = (cx, info, ret);
    }
}

impl<Cx: ?Sized, E> Hooks<Cx, E> for () {}

impl<Cx: ?Sized, E, H: Hooks<Cx, E> + ?Sized> Hooks<Cx, E> for &H {
    #[inline]
    fn filter(&self, cx: &mut Cx, info: &SyscallInfo) -> Result<(), E> {
        (**self).filter(cx, info)
    }

    #[inline]
    fn on_return(&self, cx: &mut Cx, info: &SyscallInfo, ret: &Result<usize, E>) {
        (**self).on_return(cx, info, ret)
    }
}

impl<Cx: ?Sized, E, H: Hooks<Cx, E>> Hooks<Cx, E> for Option<H> {
    #[inline]
    fn filter(&self, cx: &mut Cx, info: &SyscallInfo) -> Result<(), E> {
        match self {
            Some(h) => h.filter(cx, info),
            None => Ok(()),
        }
    }

    #[inline]
    fn on_return(&self, cx: &mut Cx, info: &SyscallInfo, ret: &Result<usize, E>) {
        if let Some(h) = self {
            h.on_return(cx, info, ret)
        }
    }
}

macro_rules! tuple_hooks {
    ($($h:ident $i:tt),+ ; $($r:tt),+) => {
        impl<Cx: ?Sized, E, $($h: Hooks<Cx, E>),+> Hooks<Cx, E> for ($($h,)+) {
            #[inline]
            fn filter(&self, cx: &mut Cx, info: &SyscallInfo) -> Result<(), E> {
                $(self.$i.filter(cx, info)?;)+

                Ok(())
            }

            #[inline]
            fn on_return(&self, cx: &mut Cx, info: &SyscallInfo, ret: &Result<usize, E>) {
                $(self.$i.on_return(cx, info, ret);)+
            }
        }
    }
}

tuple_hooks!(A 0; 0);
tuple_hooks!(A 0, B 1; 1, 0);
tuple_hooks!(A 0, B 1, C  2; 2, 1, 0);
tuple_hooks!(A 0, B 1, C 2, D 3; 3, 2, 1, 0);

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq)]
    struct E(u16);

    impl ErrorCode for E {
        const NOSYS: Self = E(38);
        const INVAL: Self = E(22);

        fn to_code(self) -> u16 {
            self.0
        }

        fn from_code(code: u16) -> Self {
            E(code)
        }
    }

    #[test]
    fn roundtrip() {
        for v in [0, 1, 42, usize::MAX - MAX_ERRNO as usize] {
            assert_eq!(decode::<E>(encode::<E>(Ok(v))), Ok(v));
        }

        for c in [1, 22, MAX_ERRNO] {
            assert_eq!(decode::<E>(encode::<E>(Err(E(c)))), Err(E(c)));
        }
    }

    #[test]
    fn signed_args_sign_extend() {
        assert_eq!((-1i32).into_raw(), usize::MAX);
        assert_eq!(i32::from_raw(usize::MAX), Some(-1));
        assert_eq!(i32::from_raw(1 << 40), None);
        assert_eq!(u32::from_raw(usize::MAX), None);
        assert_eq!(bool::from_raw(2), None);
    }
}
