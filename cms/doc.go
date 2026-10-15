// Package cms encrypts and decrypts CMS EnvelopedData (RFC 5652 §6) for the CMP
// proof-of-possession methods that need it: the encrypted certificate and the
// challenge-response exchange (RFC 9810 §5.2.8.3).
//
// An EnvelopedData built here has exactly one recipient, as RFC 9810 §5.2.2
// requires, and carries the content as id-data. Three key management techniques
// are supported:
//
//   - RSA key transport with RSAES-OAEP (RFC 8017, RFC 4055)
//   - ephemeral-static ECDH key agreement on P-256, P-384 and P-521 (RFC 5753)
//   - ML-KEM-768 and ML-KEM-1024 through KEMRecipientInfo (RFC 9629, RFC 9936)
//
// [Encrypt] chooses the algorithms from the recipient key. It always uses
// AES-256-CBC for the content and AES-256 key wrap for the content-encryption
// key. RSA uses OAEP with SHA-256. ECDH uses the X9.63 KDF with SHA-256, SHA-384
// or SHA-512 to match the curve, as RFC 9481 §4.1.2 and Table 2 pair them.
// ML-KEM uses HKDF with SHA-256 as RFC 9936 §3 requires.
//
// [Decrypt] also accepts AES-128 and AES-192, the SHA-1 and SHA-224 KDF variants
// of ECDH and HKDF with SHA-384 or SHA-512. For ML-KEM it also accepts the ANS
// X9.44 KDF2 and KDF3 of RFC 9690 Appendix B with SHA-224, SHA-256, SHA-384 or
// SHA-512, because Bouncy Castle uses KDF3 with SHA-256 by default. RSA PKCS #1
// v1.5 key transport is refused because its decryption is open to padding oracle
// attacks.
//
// ML-KEM-512 is not supported, because the Go standard library does not
// implement it.
package cms
