# sysabi

Define a syscall ABI once and generate both halves of it from the same source.

```rust
#[syscall::abi(
    abi = "example",
    version = 2,
    errno = Errno,
)]
pub trait Demo {
    /// Terminate the calling thread.
    #[syscall(nr = 0)]
    fn exit(code: i32) -> !;

    #[syscall(nr = 1)]
    unsafe fn write(fd: u32, buf: *const u8, len: usize) -> usize;

    #[syscall(nr = 2, since = 2)]
    fn getpid() -> u32;
}
```

Generated in a module named after the trait (`demo` or `module = ...`):
- `demo::ABI`: an [`AbiDesc`] with the name + version
- `demo::nr::WRITE`, ...: syscall numbers
- `demo::SYSCALLS`: [`SyscallDesc`] per syscall

`kernel` feature:
- `trait Demo` is rewritten into the handler trait implemented by the kernel:
  `fn write(&self, cx: &mut Self::Context, fd: u32, buf: *const u8, len: usize) -> Result<usize, Errno>`
- `demo::kernel::dispatch(&handler, &hooks, cx, nr, args) -> usize` decodes a trap, runs
  [`Hooks::filter`], calls handler, runs [`Hooks::on_return`], encodes the result

`user` feature:
- `demo::user::write(fd, buf, len) -> Result<usize, Errno>` and other syscalls, which trap into the kernel
  with the calling convention in [`arch`], and syscalls declared `unsafe fn` get `unsafe` stubs. The rest
  are safe.

Both features can be enabled simultaneously, for example in a full kernel + userspace environment.

# Return values

The return type written in the definition is on success; errors are always the ABI's given `Errno` type. `-> !` becomes `Result<Infallible, Errno>`, and a missing return type becomes `()`.

On the wire, results use Linux conventions: success values returned as-is, errors returned as `-code`, with codes in `1..=MAX_ERRNO`.

# Add to your project

To use `sysabi`, add it to your `Cargo.toml` as a dependency with a Git source:

```toml
[dependencies]
sysabi = { git = "https://github.com/s0uthview/sysabi.git" }
```