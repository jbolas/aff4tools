# Compiling aff4tools for Mac or Linux

These instructions will help you compile `aff4tools` (the command-line binary) and `libaff4` (the C ABI shared or static library). 
The project is developed and tested on macOS. Linux support is theoretically in place but untested.

## Prerequisites

You need Rust 1.85 or newer. Both crates declare `edition = "2024"`, which older compilers reject outright. Check with:

```sh
cargo --version
```

Install from [rustup.rs](https://rustup.rs) if the command is missing. On
Linux, a distribution `rustc` is often too old — prefer rustup over the
package manager.

You also need your platform's linker and SDK to produce a binary.

- For **macOS** — the Xcode Command Line Tools. Run `xcode-select --install` once, or
  check with `xcode-select -p`. The full Xcode app is not required.
- For **Linux** — you need `build-essential` (Debian, Ubuntu) or `gcc` (Fedora, Arch) which should already be there.

---

## 1. Compile `aff4tools`, the CLI

The build is identical on macOS and Linux. Expect a lot of Rust crate downloads the first time you build.

```sh
git clone https://github.com/jbolas/aff4tools aff4tools
cd aff4tools
cargo build --release
```

The binary lands at `target/release/aff4tools`. Without changing directories, confirm it runs:

```sh
./target/release/aff4tools --version
./target/release/aff4tools info <container.aff4>
```

Install onto `PATH` which places it in `~/.cargo/bin`:
```sh
cargo install --path .
```

If you're on Linux, for good measure, run the tests. Just get ready for a lot more crates to be downloaded and compiled.

```sh
cargo test
```

There are more tests that use reference images. To run these tests, get the images and run again with the `--features corpus` flag:

```sh
./utilities/fetch-corpus.sh
cargo test --features corpus
```

The script downloads them at pinned commits into `~/.cache/aff4tools/corpus`,
which is where the tests look by default. Pass a directory to put them
elsewhere, then set `AFF4_TEST_IMAGES` to match. See [testing.md](testing.md).

---

## 2: Compile `libaff4`, the C library

`aff4tools-ffi` exposes the C ABI. Its `[lib]` section renames the artifact to
`aff4` and requests three crate types, so one build produces both a shared and
a static library:

```sh
cargo build --release -p aff4tools-ffi
```

| Platform | Shared | Static |
|---|---|---|
| Linux | `target/release/libaff4.so` | `target/release/libaff4.a` |
| macOS | `target/release/libaff4.dylib` | `target/release/libaff4.a` |

The public header is `aff4tools-ffi/include/libaff4-c.h`. It declares fourteen
functions — `AFF4_open`, `AFF4_read`, `AFF4_close`, the property getters, and
the message helpers — and is already wrapped in `extern "C"` for C++ callers.

### Linking a C consumer

The compile line is the same on both systems; only the runtime-path flag
differs, because each platform resolves shared libraries its own way.

**macOS**, against the shared library:

```sh
cc -o consumer consumer.c \
   -I aff4tools-ffi/include \
   -L target/release -laff4 \
   -Wl,-rpath,@loader_path
```

**Linux**, against the shared library:

```sh
cc -o consumer consumer.c \
   -I aff4tools-ffi/include \
   -L target/release -laff4 \
   -Wl,-rpath,'$ORIGIN'
```

`@loader_path` and `$ORIGIN` mean the same thing — "look beside the
executable" — so the library needs to sit next to the binary you just built.
Without the flag, set `DYLD_LIBRARY_PATH` (macOS) or `LD_LIBRARY_PATH` (Linux)
to `target/release` at run time.

Against the static library, Linux needs the platform libraries Rust's runtime
depends on; macOS needs nothing extra:

```sh
# macOS
cc -o consumer consumer.c -I aff4tools-ffi/include target/release/libaff4.a

# Linux
cc -o consumer consumer.c -I aff4tools-ffi/include target/release/libaff4.a \
   -lpthread -ldl -lm
```

`aff4tools-ffi/tests/consumer.c` is a working example. It uses
`<CommonCrypto/CommonDigest.h>` for its SHA-256, which is macOS-only —
substitute OpenSSL (`-lcrypto`) or any other digest to build it on Linux.
Nothing in `libaff4-c.h` itself requires CommonCrypto.

### Verifying the ABI

```sh
cargo test -p aff4tools-ffi
```

These are gated the same way the library's are, and resolve the corpus the
same way: `AFF4_TEST_IMAGES` if set, otherwise `~/.cache/aff4tools/corpus`
where `fetch-corpus.sh` puts it.

---

## Join the cause! Test on Linux!

**Block-device sizing works on macOS and Linux, but Linux is insufficiently tested.**
`src/write/device.rs` asks the driver for the device's size. macOS multiplies
`DKIOCGETBLOCKCOUNT` by `DKIOCGETBLOCKSIZE`; Linux asks for `BLKGETSIZE64`.

On Linux, before relying on `acquire --device`, check the device block size manually:
```sh
sudo blockdev --getsize64 /dev/sdX     # what the kernel says
```
and confirm the container's `size` matches. 

**Symlink and permission handling is tuned to macOS.** The special cases in
`logical.rs` around unreadable directories were derived from macOS behavior.
Linux will present different permission issues with `acquire --logical`.

## What about Windows?

Windows is not supported. But I would think something like this would build the CLI tool:

```powershell
cargo build --release
.\target\release\aff4tools.exe --version
```

Claude says: Use the MSVC toolchain (`stable-x86_64-pc-windows-msvc`, rustup's
default), which needs the Visual Studio Build Tools with the "Desktop
development with C++" workload for its linker. The GNU toolchain also
compiles the CLI if you prefer it.

Windows is untested against real containers. Don't submit issues about it, please.
I would guess the read commands (`info`, `verify`, `conformance`) might work ok, 
but anything that writes  will encounter all the usual path syntax and POSIX incompatibility problems.

## If the build fails

If you get `feature edition2024 is required`, the toolchain predates 1.85. Run `rustup update stable`.

The error `linker 'cc' not found` on Linux means you must  install `build-essential` (Debian,
Ubuntu) or `gcc` (Fedora, Arch). Rust needs a system linker even though it compiles no C here.

On macOS, `invalid active developer path` means that the Command Line Tools are missing or 
unselected, so `/usr/bin/cc` has nothing to forward to. Run `xcode-select --install`.

Other build failures? I have faith you can solve them.