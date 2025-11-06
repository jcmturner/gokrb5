package client

// PKINIT AS Exchange Support
// Reference: RFC 4556

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"

	gokrb5crypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// PKInitState stores temporary state for a PKINIT exchange
type PKInitState struct {
	DHKeyPair    *gokrb5crypto.DHKeyPair
	ClientNonce  []byte
	Nonce        int
	ReqBodyBytes []byte
}

var pkInitState *PKInitState

// setPKInitPAData adds PKINIT pre-authentication data to the AS_REQ
func setPKInitPAData(cl *Client, ASReq *messages.ASReq) error {
	// Validate certificate
	cert := cl.Credentials.Certificate()
	privateKey := cl.Credentials.PrivateKey()

	if cert == nil || privateKey == nil {
		return krberror.Errorf(nil, krberror.ConfigError, "PKINIT: certificate or private key is nil")
	}

	// Use the same nonce as in the AS-REQ body
	// RFC 4556 requires that the PKAuthenticator nonce matches the KDC-REQ-BODY nonce
	nonce := ASReq.ReqBody.Nonce

	// Marshal the KDC-REQ-BODY to compute checksum
	reqBodyBytes, err := ASReq.ReqBody.Marshal()
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "PKINIT: failed to marshal AS-REQ body")
	}

	// Compute SHA1 checksum of KDC-REQ-BODY (RFC 4556 Section 3.2.1)
	paChecksum := gokrb5crypto.ComputeKDCReqBodyChecksum(reqBodyBytes)

	// Get RSA private key - we need the D value to use as DH private key
	// This matches the Windows AD PKINIT implementation
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return krberror.Errorf(nil, krberror.ConfigError, "PKINIT: private key must be *rsa.PrivateKey")
	}

	// Use MODP Group 2 (1024-bit) which is what Windows AD expects
	dhGroup := gokrb5crypto.DHGroupModP2

	dhKeyPair, spki, clientNonce, err := gokrb5crypto.CreateClientDHPublicValueFromKey(dhGroup, rsaKey.D)
	if err != nil {
		return krberror.Errorf(err, krberror.EncryptingError, "PKINIT: failed to create DH public value")
	}

	// Store state for later processing of AS-REP
	pkInitState = &PKInitState{
		DHKeyPair:    dhKeyPair,
		ClientNonce:  clientNonce,
		Nonce:        nonce,
		ReqBodyBytes: reqBodyBytes,
	}

	// Create PKAuthenticator
	pkAuthenticator := types.NewPKAuthenticator(nonce, paChecksum)

	// Create AuthPack with DH public value
	authPack := types.AuthPack{
		PKAuthenticator:   pkAuthenticator,
		ClientPublicValue: spki,
		ClientDHNonce:     clientNonce,
	}

	// Marshal AuthPack
	authPackBytes, err := authPack.Marshal()
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "PKINIT: failed to marshal AuthPack")
	}

	// Sign AuthPack with client's private key and wrap in CMS SignedData
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return krberror.Errorf(nil, krberror.EncryptingError, "PKINIT: private key does not implement crypto.Signer")
	}

	certChain := cl.Credentials.GetFullCertificateChain()
	signedAuthPack, err := gokrb5crypto.CreateCMSSignedData(authPackBytes, cert, signer, certChain)
	if err != nil {
		return krberror.Errorf(err, krberror.EncryptingError, "PKINIT: failed to create CMS SignedData")
	}

	// Create PA-PK-AS-REQ
	// signedAuthPack is the raw CMS SignedData ContentInfo bytes
	// The struct tag `asn1:"tag:0"` will apply IMPLICIT tagging
	paPKAsReq := types.PAPKASReq{
		SignedAuthPack: signedAuthPack,
		// TrustedCertifiers and KDCPkID are optional
	}

	// Marshal PA-PK-AS-REQ
	paPKAsReqBytes, err := paPKAsReq.Marshal()
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "PKINIT: failed to marshal PA-PK-AS-REQ")
	}

	// Add PA-PK-AS-REQ to PAData
	paData := types.PAData{
		PADataType:  patype.PA_PK_AS_REQ,
		PADataValue: paPKAsReqBytes,
	}

	// Remove any existing PA-PK-AS-REQ entries
	for i := len(ASReq.PAData) - 1; i >= 0; i-- {
		if ASReq.PAData[i].PADataType == patype.PA_PK_AS_REQ {
			ASReq.PAData = append(ASReq.PAData[:i], ASReq.PAData[i+1:]...)
		}
	}

	ASReq.PAData = append(ASReq.PAData, paData)
	return nil
}

// processPKInitASRep processes the PA-PK-AS-REP from the AS-REP and derives the reply key
func processPKInitASRep(cl *Client, ASRep *messages.ASRep, ASReq *messages.ASReq) (types.EncryptionKey, error) {
	if pkInitState == nil {
		return types.EncryptionKey{}, krberror.Errorf(nil, krberror.KRBMsgError, "PKINIT: no PKInit state available")
	}

	// Find PA-PK-AS-REP in AS-REP PAData
	var paPKAsRepData *types.PAData
	for i := range ASRep.PAData {
		if ASRep.PAData[i].PADataType == patype.PA_PK_AS_REP {
			paPKAsRepData = &ASRep.PAData[i]
			break
		}
	}

	if paPKAsRepData == nil {
		return types.EncryptionKey{}, krberror.Errorf(nil, krberror.KRBMsgError, "PKINIT: PA-PK-AS-REP not found in AS-REP")
	}

	// Parse PA-PK-AS-REP as a RawValue to determine which CHOICE was used
	var choiceValue asn1.RawValue
	_, err := asn1.Unmarshal(paPKAsRepData.PADataValue, &choiceValue)
	if err != nil {
		return types.EncryptionKey{}, krberror.Errorf(err, krberror.EncodingError, "PKINIT: failed to unmarshal PA-PK-AS-REP")
	}

	// Determine which method was used based on the tag: DH or public key encryption
	// [0] = DH method, [1] = encryption method
	if choiceValue.Tag == 0 {
		// Diffie-Hellman method - parse the DHRepInfo from the bytes
		var dhRepInfo types.DHRepInfo
		_, err = asn1.Unmarshal(choiceValue.Bytes, &dhRepInfo)
		if err != nil {
			return types.EncryptionKey{}, krberror.Errorf(err, krberror.EncodingError, "PKINIT: failed to unmarshal DHRepInfo")
		}
		return processDHInfo(cl, &dhRepInfo, ASRep)
	} else if choiceValue.Tag == 1 {
		// Public key encryption method
		return processEncKeyPack(cl, choiceValue.Bytes, ASReq, ASRep)
	}

	return types.EncryptionKey{}, krberror.Errorf(nil, krberror.KRBMsgError, "PKINIT: PA-PK-AS-REP has unexpected tag: %d", choiceValue.Tag)
}

// processDHInfo processes the DH-based PKINIT response
func processDHInfo(cl *Client, dhInfo *types.DHRepInfo, ASRep *messages.ASRep) (types.EncryptionKey, error) {
	// Verify and extract KDC's signed DH data
	kdcDHKeyInfoBytes, _, err := gokrb5crypto.VerifyCMSSignedData(dhInfo.DHSignedData, nil)
	if err != nil {
		return types.EncryptionKey{}, krberror.Errorf(err, krberror.KRBMsgError, "PKINIT: failed to verify KDC's signed DH data")
	}

	// Parse KDCDHKeyInfo
	var kdcDHKeyInfo types.KDCDHKeyInfo
	err = kdcDHKeyInfo.Unmarshal(kdcDHKeyInfoBytes)
	if err != nil {
		return types.EncryptionKey{}, krberror.Errorf(err, krberror.EncodingError, "PKINIT: failed to unmarshal KDCDHKeyInfo")
	}

	// Verify nonce matches
	if kdcDHKeyInfo.Nonce != pkInitState.Nonce {
		return types.EncryptionKey{}, krberror.Errorf(nil, krberror.KRBMsgError, "PKINIT: nonce mismatch in KDCDHKeyInfo")
	}

	// Get server nonce if present
	var serverNonce []byte
	if dhInfo.ServerDHNonce != nil {
		serverNonce = dhInfo.ServerDHNonce
	}

	// Extract KDC's DH public key from the BIT STRING
	// The SubjectPublicKey is an ASN.1 INTEGER encoded as a BIT STRING
	var kdcPublicKey *big.Int
	_, err = asn1.Unmarshal(kdcDHKeyInfo.SubjectPublicKey.Bytes, &kdcPublicKey)
	if err != nil {
		return types.EncryptionKey{}, krberror.Errorf(err, krberror.EncodingError, "PKINIT: failed to unmarshal KDC public key")
	}

	// Validate KDC's public key using our DH parameters
	err = gokrb5crypto.ValidateDHPublicKey(kdcPublicKey, pkInitState.DHKeyPair.Parameters)
	if err != nil {
		return types.EncryptionKey{}, krberror.Errorf(err, krberror.KRBMsgError, "PKINIT: invalid KDC DH public key")
	}

	// Compute shared secret directly
	sharedSecret, err := pkInitState.DHKeyPair.ComputeSharedSecret(kdcPublicKey)
	if err != nil {
		return types.EncryptionKey{}, krberror.Errorf(err, krberror.EncryptingError, "PKINIT: failed to compute shared secret")
	}

	// Determine encryption type to use (from AS-REP)
	etypeID := ASRep.EncPart.EType

	// Calculate prime size in bytes for proper shared secret encoding
	primeSize := (pkInitState.DHKeyPair.Parameters.Prime.BitLen() + 7) / 8

	// Derive the AS reply key from the shared secret
	replyKey, err := gokrb5crypto.PKInitDeriveKeyFromDH(
		sharedSecret,
		pkInitState.ClientNonce,
		serverNonce,
		etypeID,
		primeSize,
	)
	if err != nil {
		return types.EncryptionKey{}, krberror.Errorf(err, krberror.EncryptingError, "PKINIT: failed to derive reply key from DH exchange")
	}

	return replyKey, nil
}

// processEncKeyPack processes the public key encryption-based PKINIT response
func processEncKeyPack(cl *Client, encKeyPack []byte, ASReq *messages.ASReq, ASRep *messages.ASRep) (types.EncryptionKey, error) {
	// Decrypt the EnvelopedData using client's private key
	privateKey := cl.Credentials.PrivateKey()
	decrypter, ok := privateKey.(crypto.Decrypter)
	if !ok {
		return types.EncryptionKey{}, krberror.Errorf(nil, krberror.EncryptingError, "PKINIT: private key does not implement crypto.Decrypter")
	}

	replyKeyPackBytes, err := gokrb5crypto.DecryptCMSEnvelopedData(encKeyPack, decrypter)
	if err != nil {
		return types.EncryptionKey{}, krberror.Errorf(err, krberror.EncryptingError, "PKINIT: failed to decrypt EnvelopedData")
	}

	// Parse ReplyKeyPack
	var replyKeyPack types.ReplyKeyPack
	err = replyKeyPack.Unmarshal(replyKeyPackBytes)
	if err != nil {
		return types.EncryptionKey{}, krberror.Errorf(err, krberror.EncodingError, "PKINIT: failed to unmarshal ReplyKeyPack")
	}

	// Verify asChecksum (checksum of the AS-REQ using the reply key)
	// The checksum should be computed over the same KDC-REQ-BODY that was in the request
	expectedChecksum := computeASReqChecksum(replyKeyPack.ReplyKey, pkInitState.ReqBodyBytes)
	if !bytes.Equal(replyKeyPack.ASChecksum.Checksum, expectedChecksum) {
		return types.EncryptionKey{}, krberror.Errorf(nil, krberror.KRBMsgError, "PKINIT: AS-REQ checksum verification failed")
	}

	return replyKeyPack.ReplyKey, nil
}

// computeASReqChecksum computes the checksum of AS-REQ body for verification (RFC 4556 Section 3.2.4)
func computeASReqChecksum(key types.EncryptionKey, reqBodyBytes []byte) []byte {
	// For public key encryption method, this is an HMAC checksum
	// Key usage: 6 (per RFC 4556)
	et, err := gokrb5crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil
	}
	cksum, err := et.GetChecksumHash(key.KeyValue, reqBodyBytes, 6)
	if err != nil {
		return nil
	}
	return cksum
}

// Custom verification for PKINIT AS-REP
// This extends the standard AS-REP verification to handle PKINIT-derived keys
func verifyPKInitASRep(cl *Client, ASRep *messages.ASRep, ASReq *messages.ASReq) error {
	// First derive the reply key from PKINIT exchange
	replyKey, err := processPKInitASRep(cl, ASRep, ASReq)
	if err != nil {
		return err
	}

	// Decrypt the EncPart using the derived reply key
	b, err := gokrb5crypto.DecryptEncPart(ASRep.EncPart, replyKey, uint32(keyUsageASRepEncPart))
	if err != nil {
		return krberror.Errorf(err, krberror.DecryptingError, "PKINIT: failed to decrypt AS-REP EncPart")
	}

	// Unmarshal the decrypted EncKDCRepPart
	var encPart messages.EncKDCRepPart
	err = encPart.Unmarshal(b)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "PKINIT: failed to unmarshal EncKDCRepPart")
	}

	// Verify nonce matches
	if encPart.Nonce != ASReq.ReqBody.Nonce {
		return krberror.Errorf(nil, krberror.KRBMsgError, "PKINIT: nonce mismatch in AS-REP (expected: %d, got: %d)", ASReq.ReqBody.Nonce, encPart.Nonce)
	}

	// Set the decrypted part in ASRep
	ASRep.DecryptedEncPart = encPart

	return nil
}

// Key usage constant for AS-REP EncPart
const keyUsageASRepEncPart = 3

// isPKInitResponse checks if the AS-REP contains PKINIT PA-DATA
func isPKInitResponse(ASRep *messages.ASRep) bool {
	for i := range ASRep.PAData {
		if ASRep.PAData[i].PADataType == patype.PA_PK_AS_REP {
			return true
		}
	}
	return false
}
