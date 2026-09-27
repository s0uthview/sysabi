//! Run with `cargo test --features kernel,user`
#![cfg(all(feature = "kernel", feature = "user"))]

use std::cell::RefCell;

use sysabi::{ErrorCode, Hooks, SyscallInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub u16);

impl Errno {
    pub const EPERM: Self = Self(1);
    pub const EBADF: Self = Self(9);
    pub const EINVAL: Self = Self(22);
    pub const ENOSYS: Self = Self(38);
}

impl ErrorCode for Errno {
    const NOSYS: Self = Self::ENOSYS;
    const INVAL: Self = Self::EINVAL;

    fn to_code(self) -> u16 {
        self.0
    }

    fn from_code(code: u16) -> Self {
        Self(code)
    }
}

// numbers borrowed from Linux x86_64, so the user half can be tested
// against host kernel
#[sysabi::abi(
    abi = "demo",
    version = 2,
    errno = Errno
)]
pub trait Demo {
    /// Write `len` bytes from `buf` -> `fd`.
    #[syscall(nr = 1)]
    unsafe fn write(fd: u32, buf: *const u8, len: usize) -> usize;

    #[syscall(nr = 39, since = 2)]
    fn getpid() -> u32;

    #[syscall(nr = 60)]
    fn exit(code: i32) -> !;

    #[syscall(nr = 500)]
    fn set_flag(on: bool);
}

#[test]
fn metadata() {
    assert_eq!(demo::ABI.name, "demo");
    assert_eq!(demo::ABI.version, 2);
    assert_eq!(demo::nr::GETPID, 39);

    let w = demo::lookup(demo::nr::WRITE).unwrap();

    assert_eq!(w.name, "write");
    assert_eq!(w.args[1].name, "buf");
    assert_eq!(w.args[1].ty, "*const u8");
    assert!(w.is_unsafe);
    assert_eq!(demo::lookup(39).unwrap().since, 2);
    assert!(demo::lookup(2).is_none());
}

struct Proc {
    pid: u32,
    out: Vec<u8>,
    flag: bool,
}

struct Kernel;

impl Demo for Kernel {
    type Context = Proc;

    fn write(&self, cx: &mut Proc, fd: u32, buf: *const u8, len: usize) -> Result<usize, Errno> {
        if fd != 1 {
            return Err(Errno::EBADF);
        }

        cx.out.extend_from_slice(unsafe { std::slice::from_raw_parts(buf, len) });

        Ok(len)
    }

    fn getpid(&self, cx: &mut Proc) -> Result<u32, Errno> {
        Ok(cx.pid)
    }

    fn exit(&self, _cx: &mut Proc, _code: i32) -> Result<std::convert::Infallible, Errno> {
        Err(Errno::EPERM)
    }

    fn set_flag(&self, cx: &mut Proc, on: bool) -> Result<(), Errno> {
        cx.flag = on;

        Ok(())
    }
}

struct NoExit;

impl Hooks<Proc, Errno> for NoExit {
    fn filter(&self, _cx: &mut Proc, info: &SyscallInfo) -> Result<(), Errno> {
        match info.nr {
            demo::nr::EXIT => Err(Errno::EPERM),
            _ => Ok(()),
        }
    }
}

#[derive(Default)]
struct Tracer(RefCell<Vec<String>>);

impl Hooks<Proc, Errno> for Tracer {
    fn on_return(&self, _cx: &mut Proc, info: &SyscallInfo, ret: &Result<usize, Errno>) {
        self.0.borrow_mut().push(format!("{info} = {ret:?}"));
    }
}

fn proc() -> Proc {
    Proc { pid: 7, out: Vec::new(), flag: false }
}

#[test]
fn dispatch_calls_handler() {
    let mut p = proc();
    let msg = b"hi";
    let ret = demo::kernel::dispatch(&Kernel, &(), &mut p, 1, [1, msg.as_ptr() as usize, 2, 0, 0, 0]);

    assert_eq!(ret, 2);
    assert_eq!(p.out, b"hi");
    assert_eq!(demo::kernel::dispatch(&Kernel, &(), &mut p, 39, [0; 6]), 7);
}

#[test]
fn dispatch_errors() {
    let mut p = proc();
    let err = |raw| sysabi::decode::<Errno>(raw).unwrap_err();

    assert_eq!(err(demo::kernel::dispatch(&Kernel, &(), &mut p, 1, [2, 0, 0, 0, 0, 0])), Errno::EBADF);
    assert_eq!(err(demo::kernel::dispatch(&Kernel, &(), &mut p, 1234, [0; 6])), Errno::ENOSYS);
    assert_eq!(err(demo::kernel::dispatch(&Kernel, &(), &mut p, 500, [2, 0, 0, 0, 0, 0])), Errno::EINVAL);
    assert_eq!(err(demo::kernel::dispatch(&Kernel, &(), &mut p, 1, [1 << 40, 0, 0, 0, 0, 0])), Errno::EINVAL);
    assert!(!p.flag);
}

#[test]
fn hooks_filter_and_trace() {
    let mut p = proc();
    let tracer = Tracer::default();
    let hooks = (NoExit, &tracer);

    let ret = demo::kernel::dispatch(&Kernel, &hooks, &mut p, 60, [0; 6]);

    assert_eq!(sysabi::decode::<Errno>(ret), Err(Errno::EPERM));
    demo::kernel::dispatch(&Kernel, &hooks, &mut p, 500, [1, 0, 0, 0, 0, 0]);
    demo::kernel::dispatch(&Kernel, &hooks, &mut p, 9999, [1, 2, 3, 4, 5, 6]);

    assert!(p.flag);

    assert_eq!(
        *tracer.0.borrow(),
        [
            "exit(code=0x0) = Err(Errno(1))",
            "set_flag(on=0x1) = Ok(0)",
            "demo#9999(0x1, 0x2, 0x3, 0x4, 0x5, 0x6) = Err(Errno(38))",
        ]
    );
}

#[test]
fn dyn_handler_and_hooks() {
    let mut p = proc();
    let handler: &dyn Demo<Context = Proc> = &Kernel;
    let hooks: &dyn Hooks<Proc, Errno> = &NoExit;

    assert_eq!(demo::kernel::dispatch(handler, hooks, &mut p, 39, [0; 6]), 7);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn user_stubs_against_linux() {
    let msg = b"sysabi: hello from the user half\n";

    assert_eq!(unsafe { demo::user::write(1, msg.as_ptr(), msg.len()) }, Ok(msg.len()));
    assert_eq!(unsafe { demo::user::write(9999, msg.as_ptr(), msg.len()) }, Err(Errno::EBADF));
    assert_eq!(demo::user::getpid(), Ok(std::process::id()));
    assert_eq!(demo::user::set_flag(true), Err(Errno::ENOSYS));
}