package pac

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/crypto"
	"github.com/jcmturner/gokrb5/crypto/engine"
	"github.com/jcmturner/gokrb5/iana/keyusage"
	"github.com/jcmturner/gokrb5/ndr"
	"github.com/jcmturner/gokrb5/types"
)

// https://msdn.microsoft.com/en-us/library/cc237950.aspx
type PACType struct {
	CBuffers           uint32
	Version            uint32
	Buffers            []PACInfoBuffer
	Data               []byte
	KerbValidationInfo *KerbValidationInfo
	CredentialsInfo    *PAC_CredentialsInfo
	ServerChecksum     *PAC_SignatureData
	KDCChecksum        *PAC_SignatureData
	ClientInfo         *PAC_ClientInfo
	S4U_DelegationInfo *S4U_DelegationInfo
	UPN_DNSInfo        *UPN_DNSInfo
	ClientClaimsInfo   *PAC_ClientClaimsInfo
	DeviceInfo         *PAC_DeviceInfo
	DeviceClaimsInfo   *PAC_DeviceClaimsInfo
	ZeroSigData        []byte
}

func (pac *PACType) Unmarshal(b []byte) error {
	var p int
	var e binary.ByteOrder = binary.LittleEndian
	pac.Data = b
	zb := make([]byte, len(b), len(b))
	copy(zb, b)
	pac.ZeroSigData = zb
	pac.CBuffers = ndr.Read_uint32(&b, &p, &e)
	pac.Version = ndr.Read_uint32(&b, &p, &e)
	buf := make([]PACInfoBuffer, pac.CBuffers, pac.CBuffers)
	for i := range buf {
		buf[i] = Read_PACInfoBuffer(&b, &p, &e)
	}
	pac.Buffers = buf
	return nil
}

// https://msdn.microsoft.com/en-us/library/cc237954.aspx
func (pac *PACType) ProcessPACInfoBuffers(key types.EncryptionKey) error {
	for _, buf := range pac.Buffers {
		p := make([]byte, buf.CBBufferSize, buf.CBBufferSize)
		copy(p, pac.Data[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)])
		switch int(buf.ULType) {
		case ULTYPE_KERB_VALIDATION_INFO:
			if pac.KerbValidationInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k KerbValidationInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing KerbValidationInfo: %v", err)
			}
			pac.KerbValidationInfo = &k
		case ULTYPE_CREDENTIALS:
			if pac.CredentialsInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k PAC_CredentialsInfo
			err := k.Unmarshal(p, key)
			if err != nil {
				return fmt.Errorf("Error processing CredentialsInfo: %v", err)
			}
			pac.CredentialsInfo = &k
		case ULTYPE_PAC_SERVER_SIGNATURE_DATA:
			if pac.ServerChecksum != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k PAC_SignatureData
			zb, err := k.Unmarshal(p)
			copy(pac.ZeroSigData[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)], zb)
			if err != nil {
				return fmt.Errorf("Error processing ServerChecksum: %v", err)
			}
			pac.ServerChecksum = &k
		case ULTYPE_PAC_KDC_SIGNATURE_DATA:
			if pac.KDCChecksum != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k PAC_SignatureData
			zb, err := k.Unmarshal(p)
			copy(pac.ZeroSigData[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)], zb)
			if err != nil {
				return fmt.Errorf("Error processing KDCChecksum: %v", err)
			}
			pac.KDCChecksum = &k
		case ULTYPE_PAC_CLIENT_INFO:
			if pac.ClientInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k PAC_ClientInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing ClientInfo: %v", err)
			}
			pac.ClientInfo = &k
		case ULTYPE_S4U_DELEGATION_INFO:
			if pac.S4U_DelegationInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k S4U_DelegationInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing S4U_DelegationInfo: %v", err)
			}
			pac.S4U_DelegationInfo = &k
		case ULTYPE_UPN_DNS_INFO:
			if pac.UPN_DNSInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k UPN_DNSInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing UPN_DNSInfo: %v", err)
			}
			pac.UPN_DNSInfo = &k
		case ULTYPE_PAC_CLIENT_CLAIMS_INFO:
			if pac.ClientClaimsInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k PAC_ClientClaimsInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing ClientClaimsInfo: %v", err)
			}
			pac.ClientClaimsInfo = &k
		case ULTYPE_PAC_DEVICE_INFO:
			if pac.DeviceInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k PAC_DeviceInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing DeviceInfo: %v", err)
			}
			pac.DeviceInfo = &k
		case ULTYPE_PAC_DEVICE_CLAIMS_INFO:
			if pac.DeviceClaimsInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k PAC_DeviceClaimsInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("Error processing DeviceClaimsInfo: %v", err)
			}
			pac.DeviceClaimsInfo = &k
		}
	}

	if ok, err := pac.validate(key); !ok {
		return err
	}

	return nil
}

func (pac *PACType) validate(key types.EncryptionKey) (bool, error) {
	if pac.KerbValidationInfo == nil {
		return false, errors.New("PAC Info Buffers does not contain a KerbValidationInfo")
	}
	if pac.ServerChecksum == nil {
		return false, errors.New("PAC Info Buffers does not contain a ServerChecksum")
	}
	if pac.KDCChecksum == nil {
		return false, errors.New("PAC Info Buffers does not contain a KDCChecksum")
	}
	if pac.ClientInfo == nil {
		return false, errors.New("PAC Info Buffers does not contain a ClientInfo")
	}
	etype, err := crypto.GetChksumEtype(int(pac.ServerChecksum.SignatureType))
	if err != nil {
		return false, err
	}
	if ok := engine.VerifyChecksum(key.KeyValue,
		pac.ServerChecksum.Signature,
		pac.ZeroSigData,
		keyusage.KERB_NON_KERB_CKSUM_SALT,
		etype); !ok {
		return false, errors.New("PAC service checksum verification failed")
	}

	return true, nil
}
