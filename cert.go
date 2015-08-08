package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

const (
	caMaxAge   = 5 * 365 * 24 * time.Hour
	leafMaxAge = 24 * time.Hour
	caUsage    = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	leafUsage = caUsage

	maxCacheSize = 1000
)

var (
	certCache = make(map[*tls.Certificate]map[string]*tls.Certificate)
	certMutex sync.RWMutex
)

// GenerateCA generates a CA cert and key pair.
func GenerateCA(name string) (certPEM, keyPEM []byte, err error) {
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(caMaxAge),
		KeyUsage:              caUsage,
		BasicConstraintsValid: true,
		IsCA:               true,
		MaxPathLen:         2,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}
	key, err := genKeyPair()
	if err != nil {
		return
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: keyDER,
	})
	return
}

// GenerateCert generates a leaf cert from ca.
func GenerateCert(ca *tls.Certificate, hosts ...string) (*tls.Certificate, error) {
	if cert := getCachedCert(ca, hosts); cert != nil {
		return cert, nil
	}

	now := time.Now().Add(-1 * time.Hour).UTC()
	if !ca.Leaf.IsCA {
		return nil, errors.New("CA cert is not a CA")
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             now,
		NotAfter:              now.Add(leafMaxAge),
		KeyUsage:              leafUsage,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	key, err := genKeyPair()
	if err != nil {
		return nil, err
	}
	x, err := x509.CreateCertificate(rand.Reader, template, ca.Leaf, key.Public(), ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, x)
	cert.PrivateKey = key
	cert.Leaf, _ = x509.ParseCertificate(x)
	cacheCert(ca, hosts, cert)
	return cert, nil
}

func genKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}

func getCachedCert(ca *tls.Certificate, hosts []string) *tls.Certificate {
	certMutex.RLock()
	defer certMutex.RUnlock()

	// Don't try to deal with multiple hosts (dynamically generated
	// mitm certs only have one host)
	if len(hosts) != 1 {
		return nil
	}
	if certCache[ca] == nil {
		return nil
	}
	h := hosts[0]
	cert := certCache[ca][h]
	if cert == nil {
		return nil
	} else if cert.Leaf.NotAfter.Before(time.Now()) {
		certCache[ca][h] = nil
		return nil
	} else {
		return cert
	}
}

func cacheCert(ca *tls.Certificate, hosts []string, cert *tls.Certificate) {
	certMutex.Lock()
	defer certMutex.Unlock()

	if len(hosts) != 1 {
		return
	}
	if certCache[ca] == nil || len(certCache[ca]) > maxCacheSize {
		certCache[ca] = make(map[string]*tls.Certificate)
	}
	certCache[ca][hosts[0]] = cert
}
