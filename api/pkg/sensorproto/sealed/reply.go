package sealed

// Single-shot sealing to a reply key (docs/architecture/task-secrets.md): the
// answer to a task secrets fetch is sealed with the envelope's suite to the
// single-use public key the sensor put in its signed request, with the
// caller's info (contract secretref.Info) and no additional data. There is
// no envelope header: the caller's wire format carries the suite and the key
// id. The sensor side (sdk-go pkg/sealedmsg) is checked against the same
// vector (testdata/task-secrets-vector-v1.json).

import (
	"crypto/hpke"
	"fmt"
)

// MaxReplyPlaintext bounds what SealToKey seals.
const MaxReplyPlaintext = 1 << 19

// SealToKey seals pt to the public key pubKey (its encoded bytes, as
// PublicKey.Bytes gives them) with info. The output is the HPKE base-mode
// single-shot output: the encapsulated key followed by the ciphertext.
func SealToKey(pubKey, info, pt []byte) ([]byte, error) {
	if len(pt) > MaxReplyPlaintext {
		return nil, fmt.Errorf("%w: plaintext too large", ErrMalformed)
	}
	pub, err := kem().NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid reply key", ErrMalformed)
	}
	kdf, aead := suite()
	ct, err := hpke.Seal(pub, kdf, aead, info, pt)
	if err != nil {
		return nil, fmt.Errorf("sealed: seal: %w", err)
	}
	return ct, nil
}

// OpenWithKey opens what SealToKey sealed to priv's public key with the same
// info. Any other key, info or a changed byte gives ErrOpen.
func OpenWithKey(priv *PrivateKey, info, ct []byte) ([]byte, error) {
	if priv == nil {
		return nil, ErrUnknownKey
	}
	kdf, aead := suite()
	pt, err := hpke.Open(priv.k, kdf, aead, info, ct)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}
