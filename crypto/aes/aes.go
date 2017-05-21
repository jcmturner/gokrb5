// AES Kerberos Encryption Types.
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/crypto/engine"
	"github.com/jcmturner/gokrb5/crypto/etype"
	"golang.org/x/crypto/pbkdf2"
)

const (
	s2kParamsZero = 4294967296
)

func s2kparamsToItertions(s2kparams string) (int, error) {
	//process s2kparams string
	//The parameter string is four octets indicating an unsigned
	//number in big-endian order.  This is the number of iterations to be
	//performed.  If the value is 00 00 00 00, the number of iterations to
	//be performed is 4,294,967,296 (2**32).
	var i uint32
	if len(s2kparams) != 8 {
		return s2kParamsZero, errors.New("Invalid s2kparams length")
	}
	b, err := hex.DecodeString(s2kparams)
	if err != nil {
		return s2kParamsZero, errors.New("Invalid s2kparams, cannot decode string to bytes")
	}
	i = binary.BigEndian.Uint32(b)
	//buf := bytes.NewBuffer(b)
	//err = binary.Read(buf, binary.BigEndian, &i)
	if err != nil {
		return s2kParamsZero, errors.New("Invalid s2kparams, cannot convert to big endian int32")
	}
	return int(i), nil
}

func IterationsToS2kparams(i int) string {
	b := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(b, uint32(i))
	return hex.EncodeToString(b)
}

func stringToKey(secret, salt, s2kparams string, e etype.EType) ([]byte, error) {
	i, err := s2kparamsToItertions(s2kparams)
	if err != nil {
		return nil, err
	}
	return stringToKeyIter(secret, salt, int(i), e)
}

func stringToKeySHA2(secret, salt, s2kparams string, e etype.EType) ([]byte, error) {
	i, err := s2kparamsToItertions(s2kparams)
	if err != nil {
		return nil, err
	}
	return stringToKeySHA2Iter(secret, salt, int(i), e), nil
}

func stringToPBKDF2(secret, salt string, iterations int, e etype.EType) []byte {
	return pbkdf2.Key([]byte(secret), []byte(salt), iterations, e.GetKeyByteSize(), e.GetHash())
}

func stringToKeyIter(secret, salt string, iterations int, e etype.EType) ([]byte, error) {
	tkey := randomToKey(stringToPBKDF2(secret, salt, iterations, e))
	return deriveKey(tkey, []byte("kerberos"), e)
}

func stringToKeySHA2Iter(secret, salt string, iterations int, e etype.EType) []byte {
	tkey := randomToKey(stringToPBKDF2(secret, salt, iterations, e))
	return deriveKeyKDF_HMAC_SHA2(tkey, []byte("kerberos"), e)
}

//https://tools.ietf.org/html/rfc8009#section-3
func KDF_HMAC_SHA2(protocolKey, label, context []byte, kl int, e etype.EType) []byte {
	//k: Length in bits of the key to be outputted, expressed in big-endian binary representation in 4 bytes.
	k := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(k, uint32(kl))

	c := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(c, uint32(1))
	c = append(c, label...)
	c = append(c, byte(uint8(0)))
	if len(context) > 0 {
		c = append(c, context...)
	}
	c = append(c, k...)

	mac := hmac.New(e.GetHash(), protocolKey)
	mac.Write(c)
	return mac.Sum(nil)[:(kl / 8)]
}

func deriveKeyKDF_HMAC_SHA2(protocolKey, label []byte, e etype.EType) []byte {
	var context []byte
	return KDF_HMAC_SHA2(protocolKey, label, context, e.GetKeySeedBitLength(), e)
}

func deriveRandomKDF_HMAC_SHA2(protocolKey, usage []byte, e etype.EType) ([]byte, error) {
	h := e.GetHash()()
	return KDF_HMAC_SHA2(protocolKey, []byte("prf"), usage, h.Size(), e), nil
}

func randomToKey(b []byte) []byte {
	return b
}

func deriveRandom(protocolKey, usage []byte, e etype.EType) ([]byte, error) {
	r, err := engine.DeriveRandom(protocolKey, usage, e.GetCypherBlockBitLength(), e.GetKeySeedBitLength(), e)
	return r, err
}

func deriveKey(protocolKey, usage []byte, e etype.EType) ([]byte, error) {
	r, err := deriveRandom(protocolKey, usage, e)
	if err != nil {
		return nil, err
	}
	return randomToKey(r), nil
}

func encryptCTS(key, iv, message []byte, e etype.EType) ([]byte, []byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return nil, nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}

	l := len(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Error creating cipher: %v", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)

	m := make([]byte, len(message))
	copy(m, message)

	//Ref: https://tools.ietf.org/html/rfc3962 section 5
	/*For consistency, ciphertext stealing is always used for the last two
	blocks of the data to be encrypted, as in [RC5].  If the data length
	is a multiple of the block size, this is equivalent to plain CBC mode
	with the last two ciphertext blocks swapped.*/
	/*The initial vector carried out from one encryption for use in a
	subsequent encryption is the next-to-last block of the encryption
	output; this is the encrypted form of the last plaintext block.*/
	if l <= aes.BlockSize {
		m, _ = engine.ZeroPad(m, aes.BlockSize)
		mode.CryptBlocks(m, m)
		return m, m, nil
	}
	if l%aes.BlockSize == 0 {
		mode.CryptBlocks(m, m)
		iv = m[len(m)-aes.BlockSize:]
		rb, _ := swapLastTwoBlocks(m, aes.BlockSize)
		return iv, rb, nil
	}
	m, _ = engine.ZeroPad(m, aes.BlockSize)
	rb, pb, lb, err := tailBlocks(m, aes.BlockSize)
	var ct []byte
	if rb != nil {
		// Encrpt all but the lats 2 blocks and update the rolling iv
		mode.CryptBlocks(rb, rb)
		iv = rb[len(rb)-aes.BlockSize:]
		mode = cipher.NewCBCEncrypter(block, iv)
		ct = append(ct, rb...)
	}
	mode.CryptBlocks(pb, pb)
	mode = cipher.NewCBCEncrypter(block, pb)
	mode.CryptBlocks(lb, lb)
	// Cipher Text Stealing (CTS) - Ref: https://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing
	// Swap the last two cipher blocks
	// Truncate the ciphertext to the length of the original plaintext
	ct = append(ct, lb...)
	ct = append(ct, pb...)
	return lb, ct[:l], nil
}

func decryptCTS(key, ciphertext []byte, e etype.EType) ([]byte, error) {
	// Copy the cipher text as golang slices even when passed by value to this method can result in the backing arrays of the calling code value being updated.
	ct := make([]byte, len(ciphertext))
	copy(ct, ciphertext)
	if len(key) != e.GetKeyByteSize() {
		return nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeySeedBitLength(), len(key))

	}
	if len(ct) < aes.BlockSize {
		return nil, fmt.Errorf("Ciphertext is not large enough. It is less that one block size. Blocksize:%v; Ciphertext:%v", aes.BlockSize, len(ct))
	}
	// Configure the CBC
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error creating cipher: %v", err)
	}
	var mode cipher.BlockMode
	//iv full of zeros
	ivz := make([]byte, e.GetConfounderByteSize())

	//If ciphertext is multiple of blocksize we just need to swap back the last two blocks and then do CBC
	//If the ciphertext is just one block we can't swap so we just decrypt
	if len(ct)%aes.BlockSize == 0 {
		if len(ct) > aes.BlockSize {
			ct, _ = swapLastTwoBlocks(ct, aes.BlockSize)
		}
		mode = cipher.NewCBCDecrypter(block, ivz)
		message := make([]byte, len(ct))
		mode.CryptBlocks(message, ct)
		return message[:len(ct)], nil
	}

	// Cipher Text Stealing (CTS) using CBC interface. Ref: https://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing
	// Get ciphertext of the 2nd to last (penultimate) block (cpb), the last block (clb) and the rest (crb)
	crb, cpb, clb, _ := tailBlocks(ct, aes.BlockSize)
	iv := ivz
	var message []byte
	if crb != nil {
		//If there is more than just the last and the penultimate block we decrypt it and the last bloc of this becomes the iv for later
		rb := make([]byte, len(crb))
		mode = cipher.NewCBCDecrypter(block, ivz)
		iv = crb[len(crb)-aes.BlockSize:]
		mode.CryptBlocks(rb, crb)
		message = append(message, rb...)
	}

	// We need to modify the cipher text
	// Decryt the 2nd to last (penultimate) block with a zero iv
	pb := make([]byte, aes.BlockSize)
	mode = cipher.NewCBCDecrypter(block, ivz)
	mode.CryptBlocks(pb, cpb)
	// number of byte needed to pad
	npb := aes.BlockSize - len(ct)%aes.BlockSize
	//pad last block using the number of bytes needed from the tail of the plaintext 2nd to last (penultimate) block
	clb = append(clb, pb[len(pb)-npb:]...)

	// Now decrypt the last block in the penultimate position (iv will be from the crb, if the is no crb it's zeros)
	// iv for the penultimate block decrypted in the last position becomes the modified last block
	lb := make([]byte, aes.BlockSize)
	mode = cipher.NewCBCDecrypter(block, iv)
	iv = clb
	mode.CryptBlocks(lb, clb)
	message = append(message, lb...)

	// Now decrypt the penultimate block in the last position (iv will be from the modified last block)
	mode = cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cpb, cpb)
	message = append(message, cpb...)

	// Truncate to the size of the original cipher text
	return message[:len(ct)], nil
}

func tailBlocks(b []byte, c int) ([]byte, []byte, []byte, error) {
	if len(b) <= c {
		return nil, nil, nil, errors.New("bytes not larger than one block so cannot tail")
	}
	// Get size of last block
	var lbs int
	if l := len(b) % aes.BlockSize; l == 0 {
		lbs = aes.BlockSize
	} else {
		lbs = l
	}
	// Get last block
	lb := b[len(b)-lbs:]
	// Get 2nd to last (penultimate) block
	pb := b[len(b)-lbs-c : len(b)-lbs]
	if len(b) > 2*c {
		rb := b[:len(b)-lbs-c]
		return rb, pb, lb, nil
	}
	return nil, pb, lb, nil
}

func swapLastTwoBlocks(b []byte, c int) ([]byte, error) {
	rb, pb, lb, err := tailBlocks(b, c)
	if err != nil {
		return nil, err
	}
	var out []byte
	if rb != nil {
		out = append(out, rb...)
	}
	out = append(out, lb...)
	out = append(out, pb...)
	return out, nil
}
