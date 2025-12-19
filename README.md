# ots

Minimal OpenTimestamps CLI client in Rust. Standalone implementation with no external OTS library dependencies.

## Install

```bash
cargo install --git https://github.com/dzatona/opentimestamps-client
```

## Usage

```bash
ots stamp file.txt          # Create timestamp
ots info file.txt.ots       # Show info
ots upgrade file.txt.ots    # Upgrade pending to Bitcoin attestation
ots verify file.txt.ots     # Verify Bitcoin attestation
```

## Build

```bash
git clone https://github.com/dzatona/opentimestamps-client
cd opentimestamps-client
cargo build --release
```

## License

MIT
