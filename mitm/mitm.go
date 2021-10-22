package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/pratik1998/compromiser/noise"
)

// Server configurations will replace these placeholders with real data
var database = map[string]string{"normal_request": "response",
	"secret": "secret_response"}

var g_private_key *big.Int

// RandomInc is a simple random number generator that uses the power of
// incrementing to produce "secure" random numbers
type RandomInc byte

func (r *RandomInc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*r)
		*r = (*r) + 1
	}
	return len(p), nil
}

func GenBadPriv() (k *big.Int) {
	k = new(big.Int).SetInt64(32) // exact value of k can be changed
	return
}

// GenerateKey returns a ecdsa keypair
func GenerateKey(c elliptic.Curve) *ecdsa.PrivateKey {
	k := g_private_key
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k                                                       // private key
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes()) // EC multiplication
	return priv
}

func GenerateEncryptedSecretRequest(private_key *big.Int, server_response []byte) []byte {

	// Setting up Global Private Key
	g_private_key = private_key

	// Generate the necessary keypairs for Noise IKSign Pattern
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	rngI := new(RandomInc)
	var privbytes [32]byte

	staticI, _ := cs.GenerateKeypair(rngI)
	// Generating private key based on the Eliptic Curve NIST P256
	ecdsakey := GenerateKey(elliptic.P256())
	// static public key of server provided as pre-message
	staticRbad, _ := noise.GenerateBadKeypair(ecdsakey.D.FillBytes(privbytes[:]))

	var cs1, _ *noise.CipherState
	hsI, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       noise.HandshakeIKSign,
		Initiator:     true,
		Prologue:      []byte("ABC"),
		StaticKeypair: staticI,
		PeerStatic:    staticRbad.Public,
		VerifyingKey:  ecdsakey.Public().(*ecdsa.PublicKey),
	})
	hsI.WriteMessage(nil, nil)
	msg := server_response
	var res []byte
	res, cs1, _, _ = hsI.ReadMessage(nil, msg)
	res, _ = cs1.Encrypt(nil, nil, []byte("secret"))
	return res
}
