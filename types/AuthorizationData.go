package types

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jcmturner/asn1"
	"github.com/jcmturner/gokrb5/iana/adtype"
	"github.com/jcmturner/gokrb5/mstypes"
	"os"
)

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.2.6

/*
AuthorizationData

-- NOTE: AuthorizationData is always used as an OPTIONAL field and
-- should not be empty.
AuthorizationData       ::= SEQUENCE OF SEQUENCE {
ad-type         [0] Int32,
ad-data         [1] OCTET STRING
}

ad-data
This field contains authorization data to be interpreted according
to the value of the corresponding ad-type field.

ad-type
	This field specifies the format for the ad-data subfield.  All
negative values are reserved for local use.  Non-negative values
are reserved for registered use.

Each sequence of type and data is referred to as an authorization
element.  Elements MAY be application specific; however, there is a
common set of recursive elements that should be understood by all
implementations.  These elements contain other elements embedded
within them, and the interpretation of the encapsulating element
determines which of the embedded elements must be interpreted, and
which may be ignored.

These common authorization data elements are recursively defined,
meaning that the ad-data for these types will itself contain a
sequence of authorization data whose interpretation is affected by
the encapsulating element.  Depending on the meaning of the
encapsulating element, the encapsulated elements may be ignored,
might be interpreted as issued directly by the KDC, or might be
stored in a separate plaintext part of the ticket.  The types of the
encapsulating elements are specified as part of the Kerberos
specification because the behavior based on these values should be
understood across implementations, whereas other elements need only
be understood by the applications that they affect.

Authorization data elements are considered critical if present in a
ticket or authenticator.  If an unknown authorization data element
type is received by a server either in an AP-REQ or in a ticket
contained in an AP-REQ, then, unless it is encapsulated in a known
authorization data element amending the criticality of the elements
it contains, authentication MUST fail.  Authorization data is
intended to restrict the use of a ticket.  If the service cannot
determine whether the restriction applies to that service, then a
security weakness may result if the ticket can be used for that
service.  Authorization elements that are optional can be enclosed in
an AD-IF-RELEVANT element.

In the definitions that follow, the value of the ad-type for the
element will be specified as the least significant part of the
subsection number, and the value of the ad-data will be as shown in
the ASN.1 structure that follows the subsection heading.

   Contents of ad-data                ad-type

   DER encoding of AD-IF-RELEVANT        1

   DER encoding of AD-KDCIssued          4

   DER encoding of AD-AND-OR             5

   DER encoding of AD-MANDATORY-FOR-KDC  8

*/

type AuthorizationData []AuthorizationDataEntry

type AuthorizationDataEntry struct {
	ADType int    `asn1:"explicit,tag:0"`
	ADData []byte `asn1:"explicit,tag:1"`
}

type ADIfRelevant AuthorizationData

type ADAndOr struct {
	ConditionCount int               `asn1:"explicit,tag:0"`
	Elements       AuthorizationData `asn1:"explicit,tag:1"`
}

type ADKDCIssued struct {
	ADChecksum Checksum          `asn1:"explicit,tag:0"`
	IRealm     string            `asn1:"optional,generalstring,explicit,tag:1"`
	Isname     PrincipalName     `asn1:"optional,explicit,tag:2"`
	Elements   AuthorizationData `asn1:"explicit,tag:3"`
}

type ADMandatoryForKDC AuthorizationData

func (a *ADKDCIssued) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

func (a *AuthorizationData) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

func (a *AuthorizationDataEntry) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

func (a AuthorizationData) GetPACType() (mstypes.PACType, error) {
	for _, ad := range a {
		if ad.ADType == adtype.AD_IF_RELEVANT {
			var ad2 AuthorizationData
			err := ad2.Unmarshal(ad.ADData)
			if err != nil {
				continue
			}
			// TODO note does tthe entry contain and AuthorizationData or AuthorizationDataEntry. Assuming the former atm.
			if ad2[0].ADType == adtype.AD_WIN2K_PAC {
				var p int
				var endian binary.ByteOrder
				endian = binary.LittleEndian
				pt := mstypes.Read_PACType(ad2[0].ADData, &p, &endian)
				err = processPAC(pt, ad2[0].ADData)
				return pt, err
			}
		}
	}
	return mstypes.PACType{}, errors.New("AuthorizationData within the ticket does not contain PAC data.")
}

func processPAC(pt mstypes.PACType, b []byte) error {
	for _, buf := range pt.Buffers {
		p := make([]byte, buf.CBBufferSize, buf.CBBufferSize)
		copy(p, b[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)])
		switch int(buf.ULType) {
		case mstypes.ULTYPE_KERB_VALIDATION_INFO:
			var bi mstypes.KerbValidationInfo
			err := bi.ReadFromStream(p)
			fmt.Fprintf(os.Stderr, "\nKInfo: %+v\n", bi)
			if err != nil {
				return err
			}
		case mstypes.ULTYPE_CREDENTIALS:

		case mstypes.ULTYPE_PAC_SERVER_SIGNATURE_DATA:

		case mstypes.ULTYPE_PAC_KDC_SIGNATURE_DATA:

		case mstypes.ULTYPE_PAC_CLIENT_INFO:

		case mstypes.ULTYPE_S4U_DELEGATION_INFO:

		case mstypes.ULTYPE_UPN_DNS_INFO:

		case mstypes.ULTYPE_PAC_CLIENT_CLAIMS_INFO:

		case mstypes.ULTYPE_PAC_DEVICE_INFO:

		case mstypes.ULTYPE_PAC_DEVICE_CLAIMS_INFO:

		}
	}
	return nil
}
