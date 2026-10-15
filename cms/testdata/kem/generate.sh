#!/bin/bash
# Regenerates the Bouncy Castle KEMRecipientInfo vectors. Needs OpenSSL 3.5 or
# newer for ML-KEM and BC_CLASSPATH naming the bcprov, bcpkix and bcutil jars.
set -euo pipefail
cd "$(dirname "$0")"
: "${BC_CLASSPATH:?set BC_CLASSPATH to the Bouncy Castle bcprov, bcpkix and bcutil jars}"

# The ML-KEM-768 seed (d || z) that kem_vectors_test.go decapsulates with.
seed=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f

openssl genpkey -algorithm ML-KEM-768 -pkeyopt "hexseed:$seed" |
	openssl pkey -pubout -outform DER |
	java -cp "$BC_CLASSPATH" BcKemVectors.java .
