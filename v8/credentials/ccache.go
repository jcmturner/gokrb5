package credentials

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	headerFieldTagKDCOffset = 1
)

// CCache is the file credentials cache as define here: https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
type CCache struct {
	Version          uint8
	Header           header
	DefaultPrincipal Principal
	Credentials      []*Credential
	Path             string
}

type header struct {
	length uint16
	fields []headerField
}

type headerField struct {
	tag    uint16
	length uint16
	value  []byte
}

// Credential cache entry Principal struct.
type Principal struct {
	Realm         string
	PrincipalName types.PrincipalName
}

// Credential holds a Kerberos client's ccache credential information.
type Credential struct {
	Client       Principal
	Server       Principal
	Key          types.EncryptionKey
	AuthTime     time.Time
	StartTime    time.Time
	EndTime      time.Time
	RenewTill    time.Time
	IsSKey       bool
	TicketFlags  asn1.BitString
	Addresses    []types.HostAddress
	AuthData     []types.AuthorizationDataEntry
	Ticket       []byte
	SecondTicket []byte
}

// LoadCCache loads a credential cache file into a CCache type.
func LoadCCache(cpath string) (*CCache, error) {
	c := new(CCache)
	b, err := os.ReadFile(cpath)
	if err != nil {
		return c, err
	}
	err = c.Unmarshal(b)
	return c, err
}

func CCacheFromCredentials(creds []Credential) *CCache {
	credentials := make([]*Credential, len(creds))
	for i, cred := range creds {
		credentials[i] = &cred
	}
	c := CCache{
		Version:          4,
		DefaultPrincipal: creds[0].Client,
		Credentials:      credentials,
	}

	return &c
}

func (c *CCache) getEndianess() binary.ByteOrder {
	if (c.Version == 1 || c.Version == 2) && isNativeEndianLittle() {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// Unmarshal a byte slice of credential cache data into CCache type.
func (c *CCache) Unmarshal(b []byte) error {
	p := 0
	//The first byte of the file always has the value 5
	if int8(b[p]) != 5 {
		return errors.New("Invalid credential cache data. First byte does not equal 5")
	}
	p++
	//Get credential cache version
	//The second byte contains the version number (1 to 4)
	c.Version = b[p]
	if c.Version < 1 || c.Version > 4 {
		return errors.New("Invalid credential cache data. Keytab version is not within 1 to 4")
	}
	p++
	//Version 1 or 2 of the file format uses native byte order for integer representations. Versions 3 & 4 always uses big-endian byte order
	var endian binary.ByteOrder
	endian = c.getEndianess()

	if c.Version == 4 {
		err := parseHeader(b, &p, c, &endian)
		if err != nil {
			return err
		}
	}
	c.DefaultPrincipal = parsePrincipal(b, &p, c, &endian)
	for p < len(b) {
		cred, err := parseCredential(b, &p, c, &endian)
		if err != nil {
			return err
		}
		c.Credentials = append(c.Credentials, cred)
	}
	return nil
}

func (c *CCache) Marshal() ([]byte, error) {
	var b []byte
	b = append(b, 5)
	b = append(b, c.Version)

	var endian binary.ByteOrder
	endian = c.getEndianess()
	if c.Version == 4 {
		header, err := c.writeHeader(endian)
		if err != nil {
			return b, err
		}
		b = append(b, header...)
	}

	princ, err := c.writePrincipal(c.DefaultPrincipal, endian)
	if err != nil {
		return b, err
	}
	b = append(b, princ...)

	for i := 0; i < len(c.Credentials); i++ {
		var cred []byte
		cred = c.writeCredential(c.Credentials[i], endian)
		b = append(b, cred...)
	}

	return b, nil
}

func parseHeader(b []byte, p *int, c *CCache, e *binary.ByteOrder) error {
	if c.Version != 4 {
		return errors.New("Credentials cache version is not 4 so there is no header to parse.")
	}
	h := header{}
	h.length = uint16(readInt16(b, p, e))
	for *p <= int(h.length) {
		f := headerField{}
		f.tag = uint16(readInt16(b, p, e))
		f.length = uint16(readInt16(b, p, e))
		f.value = b[*p : *p+int(f.length)]
		*p += int(f.length)
		if !f.valid() {
			return errors.New("Invalid credential cache header found")
		}
		h.fields = append(h.fields, f)
	}
	c.Header = h
	return nil
}

func (c *CCache) writeHeader(e binary.ByteOrder) ([]byte, error) {
	var b []byte
	i := make([]byte, 2)
	e.PutUint16(i, c.Header.length)
	b = append(b, i...)
	for _, field := range c.Header.fields {
		b = append(b, writeUint16(field.tag, e)...)
		b = append(b, writeUint16(field.length, e)...)
		b = append(b, field.value...)
	}
	if uint16(len(b))-2 != c.Header.length {
		return b, fmt.Errorf("Header length and real length differ %d != %d", len(b), c.Header.length)
	}
	return b, nil
}

// Parse the Keytab bytes of a principal into a Keytab entry's principal.
func parsePrincipal(b []byte, p *int, c *CCache, e *binary.ByteOrder) (princ Principal) {
	if c.Version != 1 {
		//Name Type is omitted in version 1
		princ.PrincipalName.NameType = readInt32(b, p, e)
	}
	nc := int(readInt32(b, p, e))
	if c.Version == 1 {
		//In version 1 the number of components includes the realm. Minus 1 to make consistent with version 2
		nc--
	}
	lenRealm := readInt32(b, p, e)
	princ.Realm = string(readBytes(b, p, int(lenRealm), e))
	for i := 0; i < nc; i++ {
		l := readInt32(b, p, e)
		princ.PrincipalName.NameString = append(princ.PrincipalName.NameString, string(readBytes(b, p, int(l), e)))
	}
	return princ
}

func (c *CCache) writePrincipal(p Principal, e binary.ByteOrder) ([]byte, error) {
	var b []byte
	if c.Version != 1 {
		b = append(b, writeUint32(uint32(p.PrincipalName.NameType), e)...)
	}
	count := uint32(len(p.PrincipalName.NameString))
	if c.Version == 1 {
		count += 1
	}
	b = append(b, writeUint32(count, e)...)

	realmLen := len(p.Realm)
	b = append(b, writeUint32(uint32(realmLen), e)...)
	for i := 0; i < realmLen; i++ {
		b = append(b, p.Realm[i])
	}

	for i := 0; i < len(p.PrincipalName.NameString); i++ {
		component := p.PrincipalName.NameString[i]
		b = append(b, writeUint32(uint32(len(component)), e)...)
		for j := 0; j < len(component); j++ {
			b = append(b, component[j])
		}
	}

	return b, nil
}

func parseCredential(b []byte, p *int, c *CCache, e *binary.ByteOrder) (cred *Credential, err error) {
	cred = new(Credential)
	cred.Client = parsePrincipal(b, p, c, e)
	cred.Server = parsePrincipal(b, p, c, e)
	key := types.EncryptionKey{}
	key.KeyType = int32(readInt16(b, p, e))
	if c.Version == 3 {
		//repeated twice in version 3
		key.KeyType = int32(readInt16(b, p, e))
	}
	key.KeyValue = readData(b, p, e)
	cred.Key = key
	cred.AuthTime = readTimestamp(b, p, e)
	cred.StartTime = readTimestamp(b, p, e)
	cred.EndTime = readTimestamp(b, p, e)
	cred.RenewTill = readTimestamp(b, p, e)
	if ik := readInt8(b, p, e); ik == 0 {
		cred.IsSKey = false
	} else {
		cred.IsSKey = true
	}
	cred.TicketFlags = types.NewKrbFlags()
	cred.TicketFlags.Bytes = readBytes(b, p, 4, e)
	l := int(readInt32(b, p, e))
	cred.Addresses = make([]types.HostAddress, l, l)
	for i := range cred.Addresses {
		cred.Addresses[i] = readAddress(b, p, e)
	}
	l = int(readInt32(b, p, e))
	cred.AuthData = make([]types.AuthorizationDataEntry, l, l)
	for i := range cred.AuthData {
		cred.AuthData[i] = readAuthDataEntry(b, p, e)
	}
	cred.Ticket = readData(b, p, e)
	cred.SecondTicket = readData(b, p, e)
	return
}

func (c *CCache) writeCredential(cred *Credential, e binary.ByteOrder) []byte {
	var b bytes.Buffer

	client, _ := c.writePrincipal(cred.Client, e)
	b.Write(client)

	server, _ := c.writePrincipal(cred.Server, e)
	b.Write(server)

	b.Write(writeUint16(uint16(cred.Key.KeyType), e))

	if c.Version == 3 {
		// Repeated twice in version 3
		b.Write(writeUint16(uint16(cred.Key.KeyType), e))
	}

	b.Write(writeUint32(uint32(len(cred.Key.KeyValue)), e))
	b.Write(cred.Key.KeyValue)

	b.Write(writeUint32(uint32(cred.AuthTime.Unix()), e))
	b.Write(writeUint32(uint32(cred.StartTime.Unix()), e))
	b.Write(writeUint32(uint32(cred.EndTime.Unix()), e))
	b.Write(writeUint32(uint32(cred.RenewTill.Unix()), e))

	if cred.IsSKey {
		b.WriteByte(byte(1))
	} else {
		b.WriteByte(byte(0))
	}

	b.Write(cred.TicketFlags.Bytes)

	b.Write(writeUint32(uint32(len(cred.Addresses)), e))
	for i := 0; i < len(cred.Addresses); i++ {
		address := cred.Addresses[i]
		b.Write(writeUint16(uint16(address.AddrType), e))
		b.Write(address.Address)
	}

	b.Write(writeUint32(uint32(len(cred.AuthData)), e))
	for i := 0; i < len(cred.AuthData); i++ {
		authEntry := cred.AuthData[i]
		b.Write(writeUint16(uint16(authEntry.ADType), e))
		b.Write(authEntry.ADData)
	}

	b.Write(writeUint32(uint32(len(cred.Ticket)), e))
	b.Write(cred.Ticket)
	b.Write(writeUint32(uint32(len(cred.SecondTicket)), e))
	b.Write(cred.SecondTicket)
	return b.Bytes()
}

// GetClientPrincipalName returns a PrincipalName type for the client the credentials cache is for.
func (c *CCache) GetClientPrincipalName() types.PrincipalName {
	return c.DefaultPrincipal.PrincipalName
}

// GetClientRealm returns the reals of the client the credentials cache is for.
func (c *CCache) GetClientRealm() string {
	return c.DefaultPrincipal.Realm
}

// GetClientCredentials returns a Credentials object representing the client of the credentials cache.
func (c *CCache) GetClientCredentials() *Credentials {
	return &Credentials{
		username: c.DefaultPrincipal.PrincipalName.PrincipalNameString(),
		realm:    c.GetClientRealm(),
		cname:    c.DefaultPrincipal.PrincipalName,
	}
}

// Contains tests if the cache contains a credential for the provided server PrincipalName
func (c *CCache) Contains(p types.PrincipalName) bool {
	for _, cred := range c.Credentials {
		if cred.Server.PrincipalName.Equal(p) {
			return true
		}
	}
	return false
}

// GetEntry returns a specific credential for the PrincipalName provided.
func (c *CCache) GetEntry(p types.PrincipalName) (*Credential, bool) {
	cred := new(Credential)
	var found bool
	for i := range c.Credentials {
		if c.Credentials[i].Server.PrincipalName.Equal(p) {
			cred = c.Credentials[i]
			found = true
			break
		}
	}
	if !found {
		return cred, false
	}
	return cred, true
}

// GetEntries filters out configuration entries an returns a slice of credentials.
func (c *CCache) GetEntries() []*Credential {
	creds := make([]*Credential, 0)
	for _, cred := range c.Credentials {
		// Filter out configuration entries
		if strings.HasPrefix(cred.Server.Realm, "X-CACHECONF") {
			continue
		}
		creds = append(creds, cred)
	}
	return creds
}

func (h *headerField) valid() bool {
	// See https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html - Header format
	switch h.tag {
	case headerFieldTagKDCOffset:
		if h.length != 8 || len(h.value) != 8 {
			return false
		}
		return true
	}
	return false
}

func readData(b []byte, p *int, e *binary.ByteOrder) []byte {
	l := readInt32(b, p, e)
	return readBytes(b, p, int(l), e)
}

func readAddress(b []byte, p *int, e *binary.ByteOrder) types.HostAddress {
	a := types.HostAddress{}
	a.AddrType = int32(readInt16(b, p, e))
	a.Address = readData(b, p, e)
	return a
}

func readAuthDataEntry(b []byte, p *int, e *binary.ByteOrder) types.AuthorizationDataEntry {
	a := types.AuthorizationDataEntry{}
	a.ADType = int32(readInt16(b, p, e))
	a.ADData = readData(b, p, e)
	return a
}

// Read bytes representing a timestamp.
func readTimestamp(b []byte, p *int, e *binary.ByteOrder) time.Time {
	return time.Unix(int64(readInt32(b, p, e)), 0)
}

func writeUint16(i uint16, e binary.ByteOrder) []byte {
	b := make([]byte, 2)
	e.PutUint16(b, i)
	return b
}

func writeUint32(i uint32, e binary.ByteOrder) []byte {
	b := make([]byte, 4)
	e.PutUint32(b, i)
	return b
}

// Read bytes representing an eight bit integer.
func readInt8(b []byte, p *int, e *binary.ByteOrder) (i int8) {
	buf := bytes.NewBuffer(b[*p : *p+1])
	binary.Read(buf, *e, &i)
	*p++
	return
}

// Read bytes representing a sixteen bit integer.
func readInt16(b []byte, p *int, e *binary.ByteOrder) (i int16) {
	buf := bytes.NewBuffer(b[*p : *p+2])
	binary.Read(buf, *e, &i)
	*p += 2
	return
}

// Read bytes representing a thirty two bit integer.
func readInt32(b []byte, p *int, e *binary.ByteOrder) (i int32) {
	buf := bytes.NewBuffer(b[*p : *p+4])
	binary.Read(buf, *e, &i)
	*p += 4
	return
}

func readBytes(b []byte, p *int, s int, e *binary.ByteOrder) []byte {
	buf := bytes.NewBuffer(b[*p : *p+s])
	r := make([]byte, s)
	binary.Read(buf, *e, &r)
	*p += s
	return r
}

func isNativeEndianLittle() bool {
	var x = 0x012345678
	var p = unsafe.Pointer(&x)
	var bp = (*[4]byte)(p)

	var endian bool
	if 0x01 == bp[0] {
		endian = false
	} else if (0x78 & 0xff) == (bp[0] & 0xff) {
		endian = true
	} else {
		// Default to big endian
		endian = false
	}
	return endian
}
