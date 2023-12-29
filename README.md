# webauthn_rp  
  
`webauthn_rp` will be a library for [Web Authentication (WebAuthn) Level 3](https://www.w3.org/TR/webauthn-3/#sctn-rp-operations)
Relying Party (RP) operations. For better cross-platform compatibility and Rust integration, it will rely on
[`ring`](https://docs.rs/ring/latest/ring/) for crypto operations; but as development progresses, it may allow the use of
[`openssl`](https://docs.rs/openssl/latest/openssl/) in a way that is compatible with [LibreSSL](https://www.libressl.org/).  
  
There will be no attempt to adhere to standards that are not accepted as "legitimate" by _actual_ cryptographers (e.g., Federal Information Processing Standards (FIPS)).  
  
### Status  
  
This package is still in development.  
  
The crate will only be tested on the `x86_64-unknown-linux-gnu` and `x86_64-unknown-openbsd` targets, but
it should work on any [Tier 1 with Host Tools](https://doc.rust-lang.org/beta/rustc/platform-support.html)
target.
