package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/fastchain/mukade/models"
	"github.com/go-openapi/strfmt"
	"log"

	"crypto/x509/pkix"
	//"encoding/pem"

	"github.com/go-openapi/runtime/client"

	mukadeclient "github.com/fastchain/mukade/client"

	//"github.com/fastchain/mukade/client/operations"
	clientoperations "github.com/fastchain/mukade/client/operations"
)

func main() {
	// Define the transport configuration
	transport := client.New("127.0.0.1:5000", "/api/v1/", []string{"http"})

	// Create the API client
	mClient := mukadeclient.New(transport, strfmt.Default)

	//preparing csr
	// Generate a private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Extract the public key from the private key
	//publicKey := &privateKey.PublicKey

	// Create a certificate request template
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"Example Co"},
			Country:      []string{"US"},
		},
		DNSNames:       []string{"example.com", "www.example.com"},
		EmailAddresses: []string{"admin@example.com"},
	}

	// Create the CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		log.Fatalf("Failed to create CSR: %v", err)
	}

	// Encode the CSR to PEM format
	csrPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	// Create a new request (example using a 'getSomething' operation)
	var cr models.CertificateRequest
	raw := string(csrPem)
	pk := "aaa"
	subj := csrTemplate.Subject.String()

	cr.PublicKey = &pk
	cr.Subject = &subj
	cr.Raw = raw

	//"publicKey":"aaa","subject":"aa","raw"

	reqparams := clientoperations.RequestCertificateParams{CertificateRequest: &cr}

	// Authentication (if required)
	// Assuming the API uses Bearer token for authentication
	//auth := client.BearerToken("your-access-token")

	//fmt.Println(cr)

	// Make the request
	response, err := mClient.Operations.RequestCertificate(&reqparams)
	if err != nil {
		log.Fatalf("Error making request: %v", err)
	}

	// Handle the response
	fmt.Println(response.Payload.ID)

	// Create a new request (example using a 'getSomething' operation)
	sigparams := clientoperations.SignRequestParams{RequestID: response.Payload.ID}

	// Make the request
	response2, err := mClient.Operations.SignRequest(&sigparams)
	if err != nil {
		log.Fatalf("Error making request: %v", err)
	}

	// Handle the response
	fmt.Println(response2.String())

	// Create a new request (example using a 'getSomething' operation)
	revokeparams := clientoperations.RevokeCertificateParams{CertificateID: response.Payload.ID}

	// Make the request
	response3, err := mClient.Operations.RevokeCertificate(&revokeparams)
	if err != nil {
		log.Fatalf("Error making request: %v", err)
	}

	// Handle the response
	fmt.Println(response3.String())

	// Create a new request (example using a 'getSomething' operation)
	crlparams := clientoperations.RequestCRLParams{}
	var inMemoryBuffer bytes.Buffer

	// Make the request
	_, err = mClient.Operations.RequestCRL(&crlparams, &inMemoryBuffer)
	if err != nil {
		log.Fatalf("Error making request: %v", err)
	}

	// Handle the response
	//fmt.Println(response4)

	// Parse the CRL
	crl, err := x509.ParseCRL(inMemoryBuffer.Bytes()[:])
	if err != nil {
		log.Fatalf("Failed to parse CRL: %v", err)
	}

	// Print out the CRL details
	fmt.Printf("Issuer: %v\n", crl.TBSCertList.Issuer)
	fmt.Printf("This Update: %v\n", crl.TBSCertList.ThisUpdate)
	fmt.Printf("Next Update: %v\n", crl.TBSCertList.NextUpdate)
	fmt.Printf("Number of Revoked Certificates: %d\n", len(crl.TBSCertList.RevokedCertificates))

	// Print details of each revoked certificate
	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		fmt.Printf("Serial Number: %v\n", revokedCert.SerialNumber)
		fmt.Printf("Revocation Time: %v\n", revokedCert.RevocationTime)
		fmt.Printf("Extensions: %v\n", revokedCert.Extensions)
		fmt.Println("---")
	}

	// Print the signature algorithm
	fmt.Printf("Signature Algorithm: %v\n", crl.SignatureAlgorithm)

	// Print the CRL signature
	//fmt.Printf("Signature: %s\n", hex.EncodeToString(crl.SignatureValue))
}
