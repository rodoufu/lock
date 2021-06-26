package pkg

import (
	"crypto/sha256"

	"github.com/rodoufu/lock/pkg/message"
)

type Message message.Message

func (m *Message) GetPublicKey() (PublicKey, error) {
	return NewPublicKey(m.PublicKey)
}

func (m *Message) Verifies() (bool, error) {
	if pub, err := m.GetPublicKey(); err != nil {
		return false, err
	} else {
		method := NewSha265Digest()
		var hashed []byte
		if hashed, err = method.Digest(m.Payload); err != nil {
			return false, err
		}
		if len(hashed) != len(m.Digest) {
			return false, nil
		}
		for i := range hashed {
			if hashed[i] != m.Digest[i] {
				return false, nil
			}
		}
		return pub.Verify(m.Digest, m.Signature), nil
	}
}

type DigestMethod interface {
	Digest([]byte) ([]byte, error)
}

type sha256Digest struct{}

func (s sha256Digest) Digest(message []byte) ([]byte, error) {
	msgHash := sha256.New()
	if _, err := msgHash.Write(message); err != nil {
		return nil, err
	}
	return msgHash.Sum(nil), nil
}

func NewSha265Digest() DigestMethod {
	return sha256Digest{}
}
