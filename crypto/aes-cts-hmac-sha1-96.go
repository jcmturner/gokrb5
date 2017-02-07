package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"strings"
)

const (
	s2kParamsZero = 4294967296
)

func AESStringToKey(secret string, salt string, s2kparams string, e EType) ([]byte, error) {
	//process s2kparams string
	//The parameter string is four octets indicating an unsigned
	//number in big-endian order.  This is the number of iterations to be
	//performed.  If the value is 00 00 00 00, the number of iterations to
	//be performed is 4,294,967,296 (2**32).
	var i int
	if s2kparams == "00 00 00 00" {
		i = s2kParamsZero
	} else {
		s := strings.Replace(s2kparams, " ", "", -1)
		if len(s) != 8 {
			return nil, errors.New("Invalid s2kparams")
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, errors.New("Invalid s2kparams")
		}
		buf := bytes.NewBuffer(b)
		binary.Read(buf, binary.BigEndian, &i)
		if i == 0 {
			i = s2kParamsZero
		}
	}

	return AESStringToKeyIter(secret, salt, i, e)
}

func AESStringToPBKDF2(secret string, salt string, iterations int, e EType) []byte {
	return pbkdf2.Key([]byte(secret), []byte(salt), iterations, e.GetKeyByteSize(), sha1.New)
}

func AESStringToKeyIter(secret string, salt string, iterations int, e EType) ([]byte, error) {
	tkey := AESRandomToKey(AESStringToPBKDF2(secret, salt, iterations, e))
	key, err := AESDeriveKey(tkey, []byte("kerberos"), e)
	return key, err
}

func AESRandomToKey(b []byte) []byte {
	return b
}

func AESDeriveRandom(protocolKey, usage []byte, e EType) ([]byte, error) {
	r, err := deriveRandom(protocolKey, usage, e.GetCypherBlockBitLength(), e.GetKeySeedBitLength(), e)
	return r, err
}

func AESDeriveKey(protocolKey, usage []byte, e EType) ([]byte, error) {
	r, err := AESDeriveRandom(protocolKey, usage, e)
	if err != nil {
		return nil, err
	}
	return AESRandomToKey(r), nil
}

func AESCTSEncrypt(key, iv, message []byte, e EType) ([]byte, []byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return nil, nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}

	l := len(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Error creating cipher: %v", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)

	//Ref: https://tools.ietf.org/html/rfc3962 section 5
	/*For consistency, ciphertext stealing is always used for the last two
	blocks of the data to be encrypted, as in [RC5].  If the data length
	is a multiple of the block size, this is equivalent to plain CBC mode
	with the last two ciphertext blocks swapped.*/
	/*The initial vector carried out from one encryption for use in a
	subsequent encryption is the next-to-last block of the encryption
	output; this is the encrypted form of the last plaintext block.*/
	if l <= aes.BlockSize {
		message, _ = zeroPad(message, aes.BlockSize)
		mode.CryptBlocks(message, message)
		return message, message, nil
	}
	if l%aes.BlockSize == 0 {
		mode.CryptBlocks(message, message)
		iv = message[len(message)-aes.BlockSize:]
		rb, _ := swapLastTwoBlocks(message, aes.BlockSize)
		return iv, rb, nil
	}
	message, _ = zeroPad(message, aes.BlockSize)
	rb, pb, lb, err := tailBlocks(message, aes.BlockSize)
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
	//TODO do we need to add the hash to the end?
}

func AESCTSDecrypt(key, ciphertext []byte, e EType) ([]byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeySeedBitLength(), len(key))

	}
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("Ciphertext is not large enough. It is less that one block size. Blocksize:%v; Ciphertext:%v", aes.BlockSize, len(ciphertext))
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
	if len(ciphertext)%aes.BlockSize == 0 {
		if len(ciphertext) > aes.BlockSize {
			ciphertext, _ = swapLastTwoBlocks(ciphertext, aes.BlockSize)
		}
		mode = cipher.NewCBCDecrypter(block, ivz)
		message := make([]byte, len(ciphertext))
		mode.CryptBlocks(message, ciphertext)
		return message[:len(ciphertext)], nil
	}

	// Cipher Text Stealing (CTS) using CBC interface. Ref: https://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing
	// Get ciphertext of the 2nd to last (penultimate) block (cpb), the last block (clb) and the rest (crb)
	crb, cpb, clb, _ := tailBlocks(ciphertext, aes.BlockSize)
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
	npb := aes.BlockSize - len(ciphertext)%aes.BlockSize
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
	return message[:len(ciphertext)], nil
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
