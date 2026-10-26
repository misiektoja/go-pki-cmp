#!/bin/bash
# Regenerates the OpenSSL key package vectors. OpenSSL signs a centrally
# generated key as id-data content that holds the raw key DER, with signed
# attributes and an issuerAndSerialNumber signer unless -keyid is given.
#
# kga.key is a test key labelled TESTING KEY so that secret scanners skip it.
set -euo pipefail
cd "$(dirname "$0")"

# kga prints kga.key with the label OpenSSL reads.
kga() { sed 's/TESTING KEY/PRIVATE KEY/' kga.key; }

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 | sed 's/PRIVATE KEY/TESTING KEY/' > kga.key
openssl req -x509 -new -key <(kga) -subj /CN=KGA -days 36500 -addext extendedKeyUsage=1.3.6.1.5.5.7.3.32 -out kga.crt
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 | openssl ec -outform DER -out sec1.der
openssl cms -sign -binary -nodetach -md sha256 -in sec1.der -signer kga.crt -inkey <(kga) -outform DER -out issuer-serial.der
openssl cms -sign -binary -nodetach -md sha256 -keyid -in sec1.der -signer kga.crt -inkey <(kga) -outform DER -out keyid.der
