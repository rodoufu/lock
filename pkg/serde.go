package pkg

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
)

func extractPublicKey(privateKey interface{}) (interface{}, error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey), nil
	default:
		return nil, fmt.Errorf("unexpected key format")
	}
}

func GenerateCertificate(
	notBefore time.Time, validFor time.Duration, host, organization, ecdsaCurve string, rsaBits int,
	ed25519Key, isCA bool,
) ([]byte, []byte, error) {
	if len(host) == 0 {
		return nil, nil, fmt.Errorf("missing required host parameter")
	}

	var priv interface{}
	var err error
	switch ecdsaCurve {
	case "":
		if ed25519Key {
			_, priv, err = ed25519.GenerateKey(rand.Reader)
		} else {
			priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
		}
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, nil, fmt.Errorf("unrecognized elliptic curve: %q", ecdsaCurve)
	}
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate private key")
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	var serialNumber *big.Int
	if serialNumber, err = rand.Int(rand.Reader, serialNumberLimit); err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate serial number")
	}

	if len(organization) == 0 {
		organization = "Acme Co"
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organization},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	var derBytes []byte
	var publicKey interface{}
	if publicKey, err = extractPublicKey(priv); err != nil {
		return nil, nil, err
	}
	if derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, publicKey, priv); err != nil {
		return nil, nil, errors.Wrap(err, "failed to create certificate")
	}

	var privBytes []byte
	if privBytes, err = x509.MarshalPKCS8PrivateKey(priv); err != nil {
		return nil, nil, errors.Wrapf(err, "unable to marshal private key:")
	}

	return derBytes, privBytes, nil
}

func SaveCertificates(publicKey, privateKey []byte, certificateFileName, keyFileName string) error {
	if len(certificateFileName) == 0 {
		certificateFileName = "cert.pem"
	}
	if err := func() (err error) {
		var certOut *os.File
		if certOut, err = os.Create(certificateFileName); err != nil {
			return errors.Wrapf(err, "failed to open %v for writing", certificateFileName)
		}
		defer func() {
			if errClose := certOut.Close(); err == nil && errClose != nil {
				err = errors.Wrapf(err, "error closing %v", certificateFileName)
			}
		}()
		if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: publicKey}); err != nil {
			return errors.Wrapf(err, "failed to write data to %v", certificateFileName)
		}

		return nil
	}(); err != nil {
		return err
	}

	if len(keyFileName) == 0 {
		keyFileName = "key.pem"
	}
	return func() (err error) {
		var keyOut *os.File
		if keyOut, err = os.OpenFile(keyFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err != nil {
			return errors.Wrapf(err, "failed to open %v for writing", keyFileName)
		}
		defer func() {
			if errClose := keyOut.Close(); err == nil && errClose != nil {
				err = errors.Wrapf(err, "error closing %v", keyFileName)
			}
		}()
		if err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}); err != nil {
			return errors.Wrapf(err, "failed to write data to %v", keyFileName)
		}

		return nil
	}()
}
