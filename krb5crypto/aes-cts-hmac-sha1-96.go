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
	r, err := deriveRandom(protocolKey, usage, e.GetCypherBlockBitLength(), e.GetKeySeedBitLength(), e.Encrypt)
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
	//fmt.Fprintf(os.Stderr, "Input:\nkey: %v\niv: %v\nmessage: %v\n", hex.EncodeToString(key), hex.EncodeToString(iv), hex.EncodeToString(message))
	if len(key) != e.GetKeyByteSize() {
		return nil, nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeySeedBitLength(), len(key))
	}
	l := len(message)
	message, _ = zeroPad(message, aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Error creating cipher: %v", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)

	ct := make([]byte, len(message))
	if l == aes.BlockSize {
		mode.CryptBlocks(ct, message)
		return ct, ct, nil
	}
	if l%aes.BlockSize == 0 {
		mode.CryptBlocks(ct, message)
		iv = ct[len(ct)-aes.BlockSize:]
		rb, _ := swapLastTwoBlocks(ct, aes.BlockSize)
		return iv, rb, nil
	}
	rb, pb, lb, err := tailBlocks(message, aes.BlockSize)
	if rb != nil {
		ct = make([]byte, len(rb))
		mode.CryptBlocks(ct, rb)
		iv = ct[len(ct)-aes.BlockSize:]
		mode = cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(pb, pb)
		mode = cipher.NewCBCEncrypter(block, pb)
		mode.CryptBlocks(lb, lb)
		ct = append(ct, lb...)
		ct = append(ct, pb...)
		return pb, ct[:l], nil
	}
	mode.CryptBlocks(pb, pb)
	fmt.Fprintf(os.Stderr, "cpb %v\n", hex.EncodeToString(pb))
	mode = cipher.NewCBCEncrypter(block, pb)
	mode.CryptBlocks(lb, lb)
	fmt.Fprintf(os.Stderr, "clb %v\n", hex.EncodeToString(lb))
	var ctx []byte
	ctx = append(ctx, lb...)
	ctx = append(ctx, pb...)
	fmt.Fprintf(os.Stderr, "ctx %v\n", hex.EncodeToString(ctx))
	return lb, ctx[:l], nil

	//Ref: https://tools.ietf.org/html/rfc3962 section 5
	/*For consistency, ciphertext stealing is always used for the last two
	blocks of the data to be encrypted, as in [RC5].  If the data length
	is a multiple of the block size, this is equivalent to plain CBC mode
	with the last two ciphertext blocks swapped.*/
	// Cipher Text Stealing (CTS) - Ref: https://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing
	// Swap the last two cipher blocks
	ct, _ = swapLastTwoBlocks(ct, aes.BlockSize)
	// Truncate the ciphertext to the length of the original plaintext
	//TODO do we need to add the hash to the beginning?
	return iv, ct[:l], nil
}

//func AESCTSEncrypt(key, message []byte, e EType) ([]byte, []byte, error) {
//	ivz := make([]byte, 16)
//	return AESEncrypt(key, ivz, message, e)
//	l := len(message)
//	//last block size
//	lbs := len(message)%aes.BlockSize
//	if len(key) != e.GetKeyByteSize() {
//		return nil, nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeySeedBitLength(), len(key))
//	}
//
//	if lbs != 0 {
//		message, _ = zeroPad(message, aes.BlockSize)
//	}
//
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, nil, fmt.Errorf("Error creating cipher: %v", err)
//	}
//	//RFC 3961: initial cipher state      All bits zero
//	iv := make([]byte, e.GetConfounderByteSize())
//	ct := make([]byte, l + e.GetConfounderByteSize())
//	mode := cipher.NewCBCEncrypter(block, iv)
//	mode.CryptBlocks(ct, message)
//	iv = ct[:aes.BlockSize]
//	ct = ct[aes.BlockSize:]
//	fmt.Fprintf(os.Stderr, "JT: len ct %v\n", len(ct))
//	ct ,_ = zeroPad(ct, aes.BlockSize)
//	fmt.Fprintf(os.Stderr, "JT: ct %v\n", hex.EncodeToString(ct))
//
//
//	if len(message) == aes.BlockSize {
//		//Ref: https://tools.ietf.org/html/rfc3962 section 5
//		//If exactly one block is to be encrypted, that block is simply encrypted with AES (also known as ECBmode).
//		return ct[e.GetConfounderByteSize():], ct[:l], nil
//	}
//	iv = ct[len(ct)-aes.BlockSize:]
//	//Ref: https://tools.ietf.org/html/rfc3962 section 5
//	/*For consistency, ciphertext stealing is always used for the last two
//	blocks of the data to be encrypted, as in [RC5].  If the data length
//	is a multiple of the block size, this is equivalent to plain CBC mode
//	with the last two ciphertext blocks swapped.*/
//	//Cipher Text Stealing (CTS) - Ref: https://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing
//	// Swap the last two cipher blocks
//	ct, _ = swapLastTwoBlocks(ct, aes.BlockSize)
//	// Truncate the ciphertext to the length of the original plaintext
//	return iv, ct, nil
//	//TODO do we need to add the hash to the beginning?
//}

func tailBlocks(b []byte, c int) ([]byte, []byte, []byte, error) {
	if len(b) < 2*c {
		return nil, nil, nil, errors.New("bytes shorter than two blocks so cannot swap")
	}
	// Get last block
	lb := b[len(b)-c:]
	// Get 2nd to last (penultimate) block
	pb := b[len(b)-2*c : len(b)-c]
	fmt.Fprintf(os.Stderr, "pb %v\nlb %v\n", hex.EncodeToString(pb), hex.EncodeToString(lb))
	if len(b) > 2*c {
		rb := b[:len(b)-2*c]
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
	fmt.Fprintf(os.Stderr, "JT: out %v\n", hex.EncodeToString(out))

	return rb, nil
}

func AESCTSDecrypt(key, ciphertext []byte, e EType) ([]byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return nil, fmt.Errorf("Incorrect keysize: expected: %v actual: %v", e.GetKeySeedBitLength(), len(key))

	}

	// Take the iv off the beginning and the hash block off the end
	iv := ciphertext[:e.GetConfounderByteSize()]
	cipherMsg := ciphertext[e.GetConfounderByteSize() : len(ciphertext)-(e.GetHMACBitLength()/8)]
	//cipherHash := ciphertext[len(ciphertext)-(e.GetHMACBitLength()/8):]

	if len(cipherMsg) < aes.BlockSize {
		return nil, fmt.Errorf("Ciphertext is not large enough. It is less that one block size. Blocksize:%v; Ciphertext:%v", aes.BlockSize, len(cipherMsg))
	}

	// Configure the CBC
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error creating cipher: %v", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	if len(cipherMsg) > aes.BlockSize {
		// Cipher Text Stealing (CTS) using CBC interface. Ref: https://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing
		// Get 2nd to last (penultimate) block
		cpb := cipherMsg[len(cipherMsg)-(len(cipherMsg)%aes.BlockSize)-aes.BlockSize : len(cipherMsg)-(len(cipherMsg)%aes.BlockSize)]
		// Get last block
		clb := cipherMsg[len(cipherMsg)-(len(cipherMsg)%aes.BlockSize):]
		//Decryt the 2nd to last (penultimate) block
		pb := make([]byte, aes.BlockSize)
		mode.CryptBlocks(pb, cpb)
		// number of byte needed to pad
		npb := aes.BlockSize - len(cipherMsg)%aes.BlockSize
		//pad last block using the number of bytes needed from the tail of the plaintext 2nd to last (penultimate) block
		clb = append(clb, pb[len(pb)-npb:]...)
		// Swap the last two cipher blocks
		cipherMsg = cipherMsg[:len(cipherMsg)-aes.BlockSize-(len(cipherMsg)%aes.BlockSize)]
		cipherMsg = append(cipherMsg, clb...)
		cipherMsg = append(cipherMsg, cpb...)
	}

	message := make([]byte, len(cipherMsg))
	mode.CryptBlocks(message, cipherMsg)
	//TODO verify checksum here
	return message, nil
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
