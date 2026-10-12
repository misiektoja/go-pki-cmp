# mockserver

Demonstrates how to implement the [`server.CA`](../../server/ca.go) interface
to build a CA server with CMP support. [support.go](support.go) answers the
RFC 9483 support messages for CA certificates, a certificate request template
and CRLs.
