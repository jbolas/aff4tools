# Compiling aff4tools

This repository builds two things:

- `aff4tools`, the command-line tool.
- `libaff4`, a C library for reading AFF4 disk images.

Both are written in Rust. Neither depends on an external C library.

Development and testing have been done on macOS. Linux builds but is less tested.
Windows is unsupported; building and running on Windows Subsystem for Linux (WSL2) works.

## Prerequisites

- **Rust 1.85 or newer.** Install it with [rustup](https://rustup.rs). Linux
  distribution packages are often too old.
- **A C compiler and linker.** You need this to build the C library, and also for two hashing dependencies.
  - On macOS: `xcode-select --install`
  - On Linux: `build-essential` (Debian, Ubuntu) or `gcc` (Fedora, Arch)

---

## 1. Build the `aff4tools` command

```sh
git clone https://github.com/jbolas/aff4tools
cd aff4tools
cargo build --release
./target/release/aff4tools --version
```

To install it into `~/.cargo/bin`:

```sh
cargo install --path .
```

To run the tests, see [testing.md](testing.md).

---

## 2. Build the `libaff4` library

`libaff4` gives C and C++ programs read access to AFF4 disk images. It
implements the C interface of [c-aff4](https://github.com/Velocidex/c-aff4):
the same header, `libaff4-c.h`, and the same thirteen functions. It adds one
function, `AFF4_free_property`.

It is built from this repository and doesn'tuse c-aff4 or
aff4-cpp-lite.

### Why use the same library name as `c-aff4`

Programs like The Sleuth Kit look for a library named `libaff4`. Giving
this library the same name lets those programs use it without changes. The
Sleuth Kit is one: its build searches for `-laff4`.

This makes it possible to run one tool with two different AFF4 implementations
and compare their output and performance.

`AFF4_version()` tells the two libraries apart. It returns `aff4tools <version>`
for this library and `libaff4 version <version>` for c-aff4.

### Limits

- **Disk images only.** It refuses AFF4-L logical containers. Use the `aff4tools` CLI command to work with AFF4-Ls.
- **C only.** c-aff4's library also exports C++ classes, but that's not currently implemented here.

### Build

```sh
cargo build --release -p aff4tools-ffi
```

| | Shared | Static |
|---|---|---|
| macOS | `target/release/libaff4.dylib` | `target/release/libaff4.a` |
| Linux | `target/release/libaff4.so` | `target/release/libaff4.a` |

The header is `aff4tools-ffi/include/libaff4-c.h`.
`aff4tools-ffi/tests/consumer.c` is an example C program.

---

## 3. Using `libaff4` with The Sleuth Kit

The Sleuth Kit's AFF4 support exists only on its `develop` branch. Building from that branch requires some extra steps.
This has been tested on macOS with Homebrew.

**1. Install autotools.** The `develop` branch includes no generated
`configure` script.

```sh
brew install autoconf automake libtool              # macOS
<or>
sudo apt install autoconf automake libtool          # Debian, Ubuntu
```

**2. Stage `libaff4`.** The Sleuth Kit expects the header under an `aff4/`
directory. Staging only the static library builds `libaff4` into The Sleuth
Kit, so no library search path needs setting.

```sh
PREFIX=$HOME/aff4-prefix
mkdir -p "$PREFIX/include/aff4" "$PREFIX/lib"
cp aff4tools-ffi/include/libaff4-c.h "$PREFIX/include/aff4/"
cp target/release/libaff4.a "$PREFIX/lib/"
```

**3. Build The Sleuth Kit.**

```sh
git clone --depth 1 --branch develop https://github.com/sleuthkit/sleuthkit.git
cd sleuthkit
./bootstrap
./configure --with-libaff4="$PREFIX"
make -j8
```

`configure` must report `libaff4 support: yes`. On Linux, if it reports `no`,
the static library may need extra system libraries:
`LIBS="-lpthread -ldl -lm" ./configure --with-libaff4="$PREFIX"`. That fix has
not been tested.

**4. Confirm AFF4 support.**

```sh
tools/imgtools/img_stat -i list
```

If successful, this list will include `aff4 (Advanced Forensic Format 4 (AFF4))`.

**5. Read a container.** Pass `-i aff4` to any tool. For a split container,
name any part; the library finds the others.

```sh
tools/vstools/mmls  -i aff4 evidence.aff4               # partitions
tools/fstools/fls   -i aff4 -o 128 evidence.aff4        # files at sector 128
tools/fstools/icat  -i aff4 -o 128 evidence.aff4 35 > file.out
```

The tools run from the build tree. `make install` installs them into
`/usr/local`.
