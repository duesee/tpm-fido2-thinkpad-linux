package attestation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
)

// this is the same cert used by github/SoftU2F
// https://github.com/github/SoftU2F/blob/master/SelfSignedCertificate/SelfSignedCertificate.m
// We resuse that cert to help reduce the ability to track
// an individual using this cert

var attestationPrivateKeyPem = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJXf4eE7P1NdnWWWfLNecw4DzAI8u33HXLZAp7dvAhZNoAoGCCqGSM49
AwEHoUQDQgAErVHcdCw3f3g4LSo/QOnjrrWeRZPygsbEgvvW1xvafOwMXI6K090K
9VZD8PwLDdfpCusOvE8SJ9e8sKkVH0luEA==
-----END EC PRIVATE KEY-----`

var attestationCertPem = `-----BEGIN CERTIFICATE-----
MIICmjCCAkCgAwIBAgIBATAKBggqhkjOPQQDAjCBsDEvMC0GA1UEAwwmRklETzIg
RW50ZXJwcmlzZSBBdHRlc3RhdGlvbiBURVNUIFJPT1QxJTAjBgkqhkiG9w0BCQEW
FnRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2Ux
DDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQH
DA1Nb3VudGFpbiBWaWV3MB4XDTIxMDUxMzEzMTkwOFoXDTI2MTEwMzEzMTkwOFow
gc0xOjA4BgNVBAMMMUZJRE8yIEVudGVycHJpc2UgQXR0ZXN0YXRpb24gQkFUQ0gg
S0VZIHByaW1lMjU2djExJTAjBgkqhkiG9w0BCQEWFnRvb2xzQGZpZG9hbGxpYW5j
ZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRp
Y2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAG
A1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErVHcdCw3
f3g4LSo/QOnjrrWeRZPygsbEgvvW1xvafOwMXI6K090K9VZD8PwLDdfpCusOvE8S
J9e8sKkVH0luEKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUHtPpmq+JmrcQYaOu
dH86lpbazmEwCgYIKoZIzj0EAwIDSAAwRQIhAI7XnL6PmeDPiAR+wOFaqkqj1/xT
n48TZucDj7hti7FEAiAWaKX5YprJ+SeIOJFpLx/fsONJDKo9TBD0nO7Y2CgBJg==
-----END CERTIFICATE-----`

var (
	CertDer    []byte
	PrivateKey *ecdsa.PrivateKey
)

func init() {
	certDer, _ := pem.Decode([]byte(attestationCertPem))
	CertDer = certDer.Bytes

	privKeyDer, _ := pem.Decode([]byte(attestationPrivateKeyPem))

	var err error
	PrivateKey, err = x509.ParseECPrivateKey(privKeyDer.Bytes)
	if err != nil {
		panic(err)
	}
}
