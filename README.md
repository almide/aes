# almide/aes

AES-128-CFB8 encryption for Almide. Hardware-accelerated on Rust target via AES-NI, pure Almide fallback for WASM.

## Usage

```almide
import aes
import bytes

let key = bytes.from_list([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
let iv = key
let state = aes.new_cfb8(key, iv)

let encrypted = aes.cfb8_encrypt(state, plaintext)
// encrypted.data   — ciphertext
// encrypted.state  — updated state for next call

let decrypted = aes.cfb8_decrypt(encrypted.state, encrypted.data)
```

## API

| Function | Type |
|---|---|
| `new_cfb8(key, iv)` | `(Bytes, Bytes) -> Cfb8State` |
| `cfb8_encrypt(state, data)` | `(Cfb8State, Bytes) -> { data: Bytes, state: Cfb8State }` |
| `cfb8_decrypt(state, data)` | `(Cfb8State, Bytes) -> { data: Bytes, state: Cfb8State }` |
| `encrypt_block(block, expanded_key)` | `(Bytes, Bytes) -> Bytes` |
| `expand_key(key)` | `Bytes -> Bytes` |

## Performance

| Target | Implementation | AES-CFB8 4096B |
|---|---|---|
| Rust | Native (aes crate, AES-NI) | ~67μs |
| WASM | Pure Almide | ~300ms |

## Install

```bash
almide add almide/aes
```
