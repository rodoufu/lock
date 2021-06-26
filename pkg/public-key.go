package pkg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
)

type PublicKey interface {
	AsBytes() ([]byte, error)
	Encrypt([]byte) ([]byte, error)
	Verify(message, signature []byte) bool
}

type rsaPublicKey struct {
	key  *rsa.PublicKey
	hash crypto.Hash
}

func (r *rsaPublicKey) AsBytes() ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(r.key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	}), nil
}

func (r *rsaPublicKey) Encrypt(message []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, r.key, message, nil)
}

func (r *rsaPublicKey) Verify(message, signature []byte) bool {
	return rsa.VerifyPKCS1v15(r.key, r.hash, message, signature) == nil
}

func NewPublicKey(pub []byte) (PublicKey, error) {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		if b, err = x509.DecryptPEMBlock(block, nil); err != nil {
			return nil, err
		}
	}
	var ifc interface{}
	if ifc, err = x509.ParsePKIXPublicKey(b); err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type %v", reflect.TypeOf(key))
	}
	return &rsaPublicKey{
		key:  key,
		hash: crypto.SHA256,
	}, nil
}

/*
func (r *rsaPrivateKey) VerifiesSignature(msgHashSum []byte, signature []byte) bool {
	return rsa.VerifyPSS(&r.key.PublicKey, crypto.SHA256, msgHashSum, signature, nil) == nil
}

*/
