package crypto

// Diffie-Hellman Key Exchange for PKINIT
// Reference: RFC 4556 Section 3.2.3

import (
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/jcmturner/gokrb5/v8/types"
)

// MODP Group 2 (1024-bit) - RFC 2409 Section 6.1
// Prime: 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }
var modpGroup2Prime = mustParseBigInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
var modpGroup2Generator = big.NewInt(2)

// MODP Group 14 (2048-bit) - RFC 3526 Section 3
var modpGroup14Prime = mustParseBigInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
var modpGroup14Generator = big.NewInt(2)

// DHParameters represents Diffie-Hellman domain parameters
type DHParameters struct {
	Prime     *big.Int
	Generator *big.Int
	GroupID   int // 2 or 14
}

// DHKeyPair represents a DH public/private key pair
type DHKeyPair struct {
	PrivateKey *big.Int
	PublicKey  *big.Int
	Parameters DHParameters
}

// DHGroup represents a supported DH group
type DHGroup int

const (
	DHGroupModP2  DHGroup = 2  // 1024-bit MODP Group
	DHGroupModP14 DHGroup = 14 // 2048-bit MODP Group
)

// GetDHParameters returns the DH parameters for a specific group
func GetDHParameters(group DHGroup) (DHParameters, error) {
	switch group {
	case DHGroupModP2:
		return DHParameters{
			Prime:     modpGroup2Prime,
			Generator: modpGroup2Generator,
			GroupID:   2,
		}, nil
	case DHGroupModP14:
		return DHParameters{
			Prime:     modpGroup14Prime,
			Generator: modpGroup14Generator,
			GroupID:   14,
		}, nil
	default:
		return DHParameters{}, fmt.Errorf("unsupported DH group: %d", group)
	}
}

// GenerateDHKeyPair generates a new DH key pair for the specified group
func GenerateDHKeyPair(group DHGroup) (*DHKeyPair, error) {
	params, err := GetDHParameters(group)
	if err != nil {
		return nil, err
	}

	// Generate random private key (exponent)
	// Private key should be in range [2, prime-2]
	maxPrivate := new(big.Int).Sub(params.Prime, big.NewInt(2))
	privateKey, err := rand.Int(rand.Reader, maxPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	privateKey.Add(privateKey, big.NewInt(2)) // Ensure it's at least 2

	// Calculate public key: g^privateKey mod p
	publicKey := new(big.Int).Exp(params.Generator, privateKey, params.Prime)

	return &DHKeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Parameters: params,
	}, nil
}

// ComputeSharedSecret computes the DH shared secret given the peer's public key
func (kp *DHKeyPair) ComputeSharedSecret(peerPublicKey *big.Int) (*big.Int, error) {
	// Validate peer's public key is in valid range
	if peerPublicKey.Cmp(big.NewInt(1)) <= 0 || peerPublicKey.Cmp(kp.Parameters.Prime) >= 0 {
		return nil, fmt.Errorf("invalid peer public key")
	}

	// Compute shared secret: peerPublicKey^privateKey mod prime
	sharedSecret := new(big.Int).Exp(peerPublicKey, kp.PrivateKey, kp.Parameters.Prime)

	return sharedSecret, nil
}

// DHDomainParameters ASN.1 structure for encoding DH parameters
// ValidationParms and DomainParameters as per X9.42
type DHDomainParameters struct {
	P *big.Int `asn1:""`
	G *big.Int `asn1:""`
	Q *big.Int `asn1:"optional"`
}

// EncodeDHPublicKey encodes a DH public key as SubjectPublicKeyInfo
func EncodeDHPublicKey(publicKey *big.Int, params DHParameters) (types.SubjectPublicKeyInfo, error) {
	// Encode DH domain parameters
	dhParams := DHDomainParameters{
		P: params.Prime,
		G: params.Generator,
		Q: big.NewInt(0),
	}
	paramsBytes, err := asn1.Marshal(dhParams)
	if err != nil {
		return types.SubjectPublicKeyInfo{}, fmt.Errorf("failed to marshal DH parameters: %v", err)
	}

	// Encode public key as INTEGER then convert to BIT STRING
	pubKeyBytes, err := asn1.Marshal(publicKey)
	if err != nil {
		return types.SubjectPublicKeyInfo{}, fmt.Errorf("failed to marshal public key: %v", err)
	}

	spki := types.SubjectPublicKeyInfo{
		Algorithm: types.AlgorithmIdentifier{
			Algorithm:  OIDDiffieHellman,
			Parameters: asn1.RawValue{FullBytes: paramsBytes},
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     pubKeyBytes,
			BitLength: len(pubKeyBytes) * 8,
		},
	}

	return spki, nil
}

// DecodeDHPublicKey decodes a DH public key from SubjectPublicKeyInfo
func DecodeDHPublicKey(spki types.SubjectPublicKeyInfo) (*big.Int, DHParameters, error) {
	// Verify algorithm is DH
	if !spki.Algorithm.Algorithm.Equal(OIDDiffieHellman) {
		return nil, DHParameters{}, fmt.Errorf("not a Diffie-Hellman public key")
	}

	// Parse DH parameters
	var dhParams DHDomainParameters
	_, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &dhParams)
	if err != nil {
		return nil, DHParameters{}, fmt.Errorf("failed to unmarshal DH parameters: %v", err)
	}

	// Determine group ID by comparing primes
	var groupID int
	if dhParams.P.Cmp(modpGroup2Prime) == 0 {
		groupID = 2
	} else if dhParams.P.Cmp(modpGroup14Prime) == 0 {
		groupID = 14
	} else {
		return nil, DHParameters{}, fmt.Errorf("unsupported DH group")
	}

	params := DHParameters{
		Prime:     dhParams.P,
		Generator: dhParams.G,
		GroupID:   groupID,
	}

	// Parse public key
	var publicKey *big.Int
	_, err = asn1.Unmarshal(spki.SubjectPublicKey.Bytes, &publicKey)
	if err != nil {
		return nil, DHParameters{}, fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	return publicKey, params, nil
}

// GenerateDHNonce generates a random nonce for DH key exchange
// The nonce should be as long as the longest supported symmetric key
func GenerateDHNonce(size int) ([]byte, error) {
	if size <= 0 {
		size = 32 // Default to 256 bits (AES-256 key size)
	}
	nonce := make([]byte, size)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DH nonce: %v", err)
	}
	return nonce, nil
}

// PKInitDeriveKeyFromDH derives the AS reply key from DH shared secret
// This is the main function for DH-based PKINIT key derivation
func PKInitDeriveKeyFromDH(sharedSecret *big.Int, clientNonce, serverNonce []byte, etypeID int32, primeSize int) (types.EncryptionKey, error) {
	// Convert shared secret to bytes (big-endian) with leading zeros
	// RFC 4556 Section 3.2.3.1 requires the shared secret to be encoded
	// with leading zeros to match the length of the modulus (prime)
	sharedSecretBytes := make([]byte, primeSize)
	secretBytes := sharedSecret.Bytes()
	copy(sharedSecretBytes[primeSize-len(secretBytes):], secretBytes)

	// Use the PKInitDeriveKey function with the byte representation
	return PKInitDeriveKey(sharedSecretBytes, clientNonce, serverNonce, etypeID)
}

// Helper function to parse big integers from hex strings
func mustParseBigInt(s string, base int) *big.Int {
	n := new(big.Int)
	n.SetString(s, base)
	return n
}

// ValidateDHPublicKey validates a DH public key
func ValidateDHPublicKey(publicKey *big.Int, params DHParameters) error {
	// Check that public key is in valid range: 2 <= publicKey < prime-1
	if publicKey.Cmp(big.NewInt(1)) <= 0 {
		return fmt.Errorf("DH public key must be greater than 1")
	}

	maxValid := new(big.Int).Sub(params.Prime, big.NewInt(1))
	if publicKey.Cmp(maxValid) >= 0 {
		return fmt.Errorf("DH public key must be less than prime-1")
	}

	return nil
}

// CreateClientDHPublicValueFromKey creates the client's DH public value using a provided private key
// This uses the RSA private key's D value as the DH private key (Windows AD approach)
func CreateClientDHPublicValueFromKey(preferredGroup DHGroup, dhPrivateKey *big.Int) (*DHKeyPair, types.SubjectPublicKeyInfo, []byte, error) {
	// Get DH parameters for the group
	params, err := GetDHParameters(preferredGroup)
	if err != nil {
		return nil, types.SubjectPublicKeyInfo{}, nil, fmt.Errorf("failed to get DH parameters: %v", err)
	}

	// Windows AD PKINIT uses the RSA private key D value directly as the DH private key
	// Even if D is larger than the DH prime, we use it directly in the exponentiation
	// The modular exponentiation (g^D mod p) handles the reduction automatically

	// Compute public key: g^privateKey mod p
	publicKey := new(big.Int).Exp(params.Generator, dhPrivateKey, params.Prime)

	// Create key pair
	keyPair := &DHKeyPair{
		PrivateKey: dhPrivateKey,
		PublicKey:  publicKey,
		Parameters: params,
	}

	// Encode as SubjectPublicKeyInfo
	spki, err := EncodeDHPublicKey(keyPair.PublicKey, keyPair.Parameters)
	if err != nil {
		return nil, types.SubjectPublicKeyInfo{}, nil, fmt.Errorf("failed to encode DH public key: %v", err)
	}

	// Generate client DH nonce
	clientNonce, err := GenerateDHNonce(32) // 256 bits for AES-256
	if err != nil {
		return nil, types.SubjectPublicKeyInfo{}, nil, fmt.Errorf("failed to generate client nonce: %v", err)
	}

	return keyPair, spki, clientNonce, nil
}
