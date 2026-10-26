#!/bin/bash
# Regenerates the OpenSSL PasswordRecipientInfo vectors, which wrap the
# content-encryption key with the RFC 3211 key wrap (id-alg-PWRI-KEK).
set -euo pipefail
cd "$(dirname "$0")"

printf 'password recipient test content' > content.txt
openssl cms -encrypt -binary -in content.txt -outform DER -aes256 -pwri_password 'shared secret' -out aes256.der
openssl cms -encrypt -binary -in content.txt -outform DER -aes128 -pwri_password 'shared secret' -out aes128.der
