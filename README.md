# OpenTimestamps Rust Client

A minimal, clean Rust CLI client for OpenTimestamps protocol.

## Installation

```bash
cargo install --git https://github.com/dzatona/rust-opentimestamps-client
```

## Usage

### Stamp a file

Create a timestamp for one or more files:

```bash
ots stamp file.txt
ots stamp file1.txt file2.txt file3.txt
```

Specify custom calendar servers:

```bash
ots stamp file.txt --calendar https://my-calendar.example.com
```

### Verify a timestamp

Verify that a timestamp is anchored in the Bitcoin blockchain:

```bash
ots verify file.txt.ots
```

This will check the Bitcoin attestation and print the timestamp date.

### Upgrade a pending timestamp

Upgrade a pending timestamp to include Bitcoin attestation:

```bash
ots upgrade file.txt.ots
```

This queries calendar servers for completed attestations.

### Show timestamp info

Display detailed information about a timestamp file:

```bash
ots info file.txt.ots
```

## Features

The client supports multiple Bitcoin verification backends via feature flags:

- `electrum` (default) - Uses Electrum protocol
- `esplora` - Uses Esplora API
- `rpc` - Uses Bitcoin Core RPC

Build with a specific backend:

```bash
cargo install --git https://github.com/dzatona/rust-opentimestamps-client --no-default-features --features esplora
```

## License

MIT
