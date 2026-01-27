# sia-indexd

Python SDK for interacting with a Sia network indexer.

## Installation

```bash
pip install sia-indexd
```

### Building from source

To build from source, you need Rust and Maturin:

```bash
python3 -m venv env
source env/bin/activate
pip install maturin
cd indexd_ffi
maturin develop
```

## Usage

```bash
python3 ./examples/python/example.py
````

## Async Support

This SDK uses async/await for all network operations. Make sure to call `uniffi_set_event_loop()` before making any async calls.
