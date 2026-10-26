// Package cms encrypts and decrypts CMS EnvelopedData (RFC 5652 §6) for the CMP
// operations that need it: the encrypted certificate and the challenge-response
// proofs of possession (RFC 9810 §5.2.8.3) and the private key that central key
// generation returns (RFC 9483 §4.1.6). It also handles the older EncryptedValue
// (RFC 4211 §2.1) that CMP version 2 peers use for an encrypted certificate.
//
// An EnvelopedData built here has exactly one recipient, as RFC 9810 §5.2.2
// requires. It carries the content as id-data or, with [EncryptSignedData], as
// id-signedData. Four key management techniques are supported:
//
//   - RSA key transport with RSAES-OAEP (RFC 8017, RFC 4055)
//   - ephemeral-static ECDH key agreement on P-256, P-384 and P-521 (RFC 5753)
//   - ML-KEM-768 and ML-KEM-1024 through KEMRecipientInfo (RFC 9629, RFC 9936)
//   - a shared secret through PasswordRecipientInfo with PBKDF2 (RFC 3211, RFC 8018)
//
// [Encrypt] chooses the algorithms from the recipient key. It always uses
// AES-256-CBC for the content and AES-256 key wrap for the content-encryption
// key. RSA uses OAEP with SHA-256. ECDH uses the X9.63 KDF with SHA-256, SHA-384
// or SHA-512 to match the curve, as RFC 9481 §4.1.2 and Table 2 pair them.
// ML-KEM uses HKDF with SHA-256 as RFC 9936 §3 requires. A [Password] uses
// PBKDF2 with HMAC-SHA256 and the AES-256 key wrap, as RFC 9481 §4.3 and §4.4
// require. OpenSSL reads only the RFC 3211 key wrap over AES-CBC, which a
// [PWRIKEKPassword] selects.
//
// [Decrypt] also accepts AES-128 and AES-192, the SHA-1 and SHA-224 KDF variants
// of ECDH and HKDF with SHA-384 or SHA-512. For ML-KEM it also accepts the ANS
// X9.44 KDF2 and KDF3 of RFC 9690 Appendix B with SHA-224, SHA-256, SHA-384 or
// SHA-512, because Bouncy Castle uses KDF3 with SHA-256 by default. It accepts
// SHAKE256 as well, which EJBCA uses. For a password it accepts both key wraps
// and PBKDF2 with HMAC-SHA1 to HMAC-SHA512, up to 10,000,000 iterations. RSA
// PKCS #1 v1.5 key transport is refused in EnvelopedData because its decryption
// is open to padding oracle attacks.
//
// [NewEncryptedValue] and [DecryptEncryptedValue] handle EncryptedValue, which
// only RSA keys can receive. CMP version 2 peers such as OpenSSL 3.0 and 3.2
// read no other form. They decrypt the key with PKCS #1 v1.5, so
// [NewEncryptedValue] uses it with AES-256-CBC. [DecryptEncryptedValue] also
// accepts AES-128, AES-192, Triple DES and RSAES-OAEP. It decrypts PKCS #1 v1.5
// so that a padding error looks like any other failure.
//
// ML-KEM-512 is not supported, because the Go standard library does not
// implement it.
package cms
