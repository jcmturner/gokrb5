package examples

// PKINIT Authentication Example
// This example demonstrates how to use certificate-based authentication (PKINIT)
// with the gokrb5 library.

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

// PKInitExample demonstrates basic PKINIT authentication
func PKInitExample() {
	// Load Kerberos configuration
	cfg, err := config.Load("/etc/krb5.conf")
	if err != nil {
		log.Fatalf("Failed to load krb5.conf: %v", err)
	}

	// Load client certificate
	certPEM, err := ioutil.ReadFile("/path/to/client-cert.pem")
	if err != nil {
		log.Fatalf("Failed to read certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatal("Failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	// Load private key
	keyPEM, err := ioutil.ReadFile("/path/to/client-key.pem")
	if err != nil {
		log.Fatalf("Failed to read private key: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		log.Fatal("Failed to decode PEM private key")
	}

	// Parse private key (adjust based on key type)
	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try parsing as PKCS1 RSA key
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse private key: %v", err)
		}
	}

	// Create client with certificate
	username := "user@EXAMPLE.COM"
	realm := "EXAMPLE.COM"

	cl := client.NewWithCertificate(username, realm, cert, privateKey, cfg)

	// Authenticate and get TGT
	err = cl.Login()
	if err != nil {
		log.Fatalf("Failed to login with PKINIT: %v", err)
	}

	fmt.Println("Successfully authenticated with PKINIT!")

	// Use the client for Kerberos operations
	// ...

	cl.Destroy()
}
