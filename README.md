# uuid

![Rust](https://github.com/DoumanAsh/uuid/workflows/Rust/badge.svg?branch=master)
[![Crates.io](https://img.shields.io/crates/v/lolid.svg)](https://crates.io/crates/lolid)
[![Documentation](https://docs.rs/lolid/badge.svg)](https://docs.rs/crate/lolid/)

Minimal`no_std` UUID implementation.

## Features:

- `prng` - Enables v4 using pseudo random, allowing unique, but predictable UUIDs;
- `orng` - Enables v4 using OS random, allowing unique UUIDs;
- `sha1` - Enables v5;
- `os_v1` - Enables v1 implementation using OS's API. Available platforms: Windows, Linux;
