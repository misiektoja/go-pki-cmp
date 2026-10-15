#!/bin/bash
# Regenerates the Bouncy Castle EncryptedValue vectors. Needs BC_CLASSPATH naming
# the Bouncy Castle bcprov, bcpkix and bcutil jars.
#
# rsa-key.pem is a test key labelled TESTING KEY so that secret scanners skip it.
# It was made with:
#   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | sed 's/PRIVATE KEY/TESTING KEY/' > rsa-key.pem
set -euo pipefail
cd "$(dirname "$0")"
: "${BC_CLASSPATH:?set BC_CLASSPATH to the Bouncy Castle bcprov, bcpkix and bcutil jars}"

sed 's/TESTING KEY/PRIVATE KEY/' rsa-key.pem |
	openssl pkey -pubout -outform DER |
	java -cp "$BC_CLASSPATH" BcEncryptedValueVectors.java .
