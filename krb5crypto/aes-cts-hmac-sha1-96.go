package krb5crypto

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
	"os"
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
	//TODO do we need to add the hash to the beginning?
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

func AESCTSDecrypt(key, ciphertext []byte, e EType) ([]byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeySeedBitLength(), len(key))

	}
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("Ciphertext is not large enough. It is less that one block size. Blocksize:%v; Ciphertext:%v", aes.BlockSize, len(ciphertext))
	}
	l := len(ciphertext)

	//cipherMsg := ciphertext[e.GetConfounderByteSize() : len(ciphertext)-(e.GetHMACBitLength()/8)]
	//cipherHash := ciphertext[len(ciphertext)-(e.GetHMACBitLength()/8):]

	// Configure the CBC
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error creating cipher: %v", err)
	}
	//mode := getMode(block, iv, ciphertext)
	var mode cipher.BlockMode
	var iv []byte

	if len(ciphertext) > aes.BlockSize && len(ciphertext)%aes.BlockSize == 0 {
		ciphertext, _ = swapLastTwoBlocks(ciphertext, aes.BlockSize)
	} else if len(ciphertext) > aes.BlockSize {
		// Cipher Text Stealing (CTS) using CBC interface. Ref: https://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing
		// Get 2nd to last (penultimate) block and the last block
		crb, cpb, clb, _ := tailBlocks(ciphertext, aes.BlockSize)
		var ct []byte
		if crb != nil {
			ct = crb
		}
		iv = getIV(crb)
		fmt.Fprintf(os.Stderr, "getIV IV: %v\n", hex.EncodeToString(iv))
		//Decryt the 2nd to last (penultimate) block
		pb := make([]byte, aes.BlockSize)
		mode = getMode(block, iv, ciphertext)
		mode.CryptBlocks(pb, cpb)
		// number of byte needed to pad
		npb := aes.BlockSize - len(ciphertext)%aes.BlockSize
		//pad last block using the number of bytes needed from the tail of the plaintext 2nd to last (penultimate) block
		clb = append(clb, pb[len(pb)-npb:]...)
		// Swap the last two cipher blocks
		ct = append(ct, clb...)
		ct = append(ct, cpb...)
		ciphertext = ct
	}
	iv = make([]byte, aes.BlockSize)
	mode = getMode(block, iv, ciphertext)

	message := make([]byte, len(ciphertext))
	mode.CryptBlocks(message, ciphertext)
	//fmt.Fprintf(os.Stderr, "plain %v\n", hex.EncodeToString(message))
	//TODO verify checksum here
	return message[:l], nil
}

//Pass the previous blocks to the one you want decrypted
func getIV(ct []byte) []byte {
	/*When decrypting, the next-to-last block of the supplied ciphertext is
	carried forward as the next initial vector.  If only one ciphertext
	block is available (decrypting one block, or encrypting one block or
	less), then that one block is carried out instead.*/
	fmt.Fprintf(os.Stderr, "getIV len: %v\n", len(ct))
	if ct == nil {
		return make([]byte, aes.BlockSize)
	}
	if len(ct) < 2*aes.BlockSize {
		return make([]byte, aes.BlockSize)
	}
	var lbs int
	if l := len(ct) % aes.BlockSize; l == 0 {
		lbs = aes.BlockSize
	} else {
		lbs = l
	}
	// Get 2nd to last (penultimate) block
	pb := ct[len(ct)-lbs-aes.BlockSize : len(ct)-lbs]
	return pb
}

func getMode(block cipher.Block, iv, ct []byte) cipher.BlockMode {
	//fmt.Fprintf(os.Stderr, "%v (%v) - iv for mode: %v\n",hex.EncodeToString(ct), len(ct), hex.EncodeToString(iv))
	return cipher.NewCBCDecrypter(block, iv)
}

/*func DEwithHMAC(key, message []byte) (ct []byte, err error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", KeySize, len(key))
	}
	if len(message)%aes.BlockSize != 0 {
		return nil, errors.New("Plaintext is not a multiple of the block size")
	}

	iv := make([]byte, NonceSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("Error creating random nonce: %v", err)
	}

	// NewCipher only returns an error with an invalid key size,
	// but the key size was checked at the beginning of the function.
	c, err := aes.NewCipher(key[:CipherKeyLength])
	if err != nil {
		return nil, fmt.Errorf("Error creating cipher: %v", err)
	}
	ctr := cipher.NewCBCEncrypter(c, iv)
	ctr.CryptBlocks(ct, message)

	h := hmac.New(sha1.New(), key[CipherKeyLength:])
	ct = append(iv, ct...)
	h.Write(ct)
	ct = h.Sum(ct)
	return ct[:HMACKeyLength], nil
}*/
