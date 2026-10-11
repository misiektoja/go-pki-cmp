package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"log"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

func ExampleNewClient() {
	c := client.NewClient("http://ca.example.com:8080/cmp",
		client.WithRecipient(pkix.Name{CommonName: "My CA"}),
		client.WithMaxPolls(30),
	)

	fmt.Printf("Client type: %T\n", c)
	// Output:
	// Client type: *client.Client
}

func ExampleClient_SendIR() {
	// Generate a new private key for the certificate request.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Configure MAC protection using a shared secret.
	creds, _ := pkicmp.NewMACCredentials([]byte("enrollment-secret"))

	// Create a CMP client pointing to the CA endpoint.
	c := client.NewClient("http://ca.example.com:8080/cmp")

	// Send an Initialization Request (IR) to enroll a new certificate.
	// This example shows the API usage pattern.
	result, err := c.SendIR(context.Background(), key, creds,
		client.WithTemplateSubject(pkix.Name{CommonName: "my-device"}),
		client.WithSender(pkix.Name{CommonName: "my-device"}),
	)
	if err != nil {
		log.Fatal(err)
	}

	_ = result // result.Certificate contains the issued certificate
}
