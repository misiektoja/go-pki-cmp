#!/bin/bash
set -e

# Generate client key, CSR and a self-signed certificate to revoke
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out test_client.key
openssl req -new -key test_client.key -subj "/CN=test" -out test_client.csr
openssl req -x509 -key test_client.key -subj "/CN=test" -days 1 -out test_client.crt

# Generate CMP messages in DER format
openssl cmp -cmd ir -csr test_client.csr -newkey test_client.key -secret pass:pass -ref myref -reqout_only ir_golden.der
openssl cmp -cmd cr -csr test_client.csr -newkey test_client.key -secret pass:pass -ref myref -reqout_only cr_golden.der
openssl cmp -cmd kur -csr test_client.csr -newkey test_client.key -secret pass:pass -ref myref -reqout_only kur_golden.der
openssl cmp -cmd p10cr -csr test_client.csr -secret pass:pass -ref myref -reqout_only p10cr_golden.der
openssl cmp -cmd rr -oldcert test_client.crt -revreason 1 -cert test_client.crt -key test_client.key -reqout_only rr_golden.der

# Generate SLH-DSA (RFC 9909) messages, which need OpenSSL 3.5 or newer
openssl genpkey -algorithm SLH-DSA-SHA2-128s -out test_slhdsa_ir.key
openssl cmp -cmd ir -newkey test_slhdsa_ir.key -subject /CN=test -secret pass:pass -ref myref -reqout_only ir_slhdsa_golden.der
openssl genpkey -algorithm SLH-DSA-SHAKE-128s -out test_slhdsa_p10cr.key
openssl req -new -key test_slhdsa_p10cr.key -subj "/CN=test" -out test_slhdsa_p10cr.csr
openssl cmp -cmd p10cr -csr test_slhdsa_p10cr.csr -secret pass:pass -ref myref -reqout_only p10cr_slhdsa_golden.der

# Cleanup intermediate files
rm test_client.key test_client.csr test_client.crt test_slhdsa_ir.key test_slhdsa_p10cr.key test_slhdsa_p10cr.csr
