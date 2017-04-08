package GSSAPI

import (
	"encoding/hex"
	"github.com/jcmturner/gokrb5/messages"
	"github.com/jcmturner/gokrb5/testdata"
	"github.com/jcmturner/gokrb5/types"
	"testing"
)

const MechToken_Hex = "6082026306092a864886f71201020201006e8202523082024ea003020105a10302010ea20703050000000000a382015d6182015930820155a003020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b10686f73742e746573742e676f6b726235a382011830820114a003020112a103020103a28201060482010230621d868c97f30bf401e03bbffcd724bd9d067dce2afc31f71a356449b070cdafcc1ff372d0eb1e7a708b50c0152f3996c45b1ea312a803907fb97192d39f20cdcaea29876190f51de6e2b4a4df0460122ed97f363434e1e120b0e76c172b4424a536987152ac0b73013ab88af4b13a3fcdc63f739039dd46d839709cf5b51bb0ce6cb3af05fab3844caac280929955495235e9d0424f8a1fb9b4bd4f6bba971f40b97e9da60b9dabfcf0b1feebfca02c9a19b327a0004aa8e19192726cf347561fa8ac74afad5d6a264e50cf495b93aac86c77b2bc2d184234f6c2767dbea431485a25687b9044a20b601e968efaefffa1fc5283ff32aa6a53cb6c5cdd2eddcb26a481d73081d4a003020112a103020103a281c70481c4a1b29e420324f7edf9efae39df7bcaaf196a3160cf07e72f52a4ef8a965721b2f3343719c50699046e4fcc18ca26c2bfc7e4a9eddfc9d9cfc57ff2f6bdbbd1fc40ac442195bc669b9a0dbba12563b3e4cac9f4022fc01b8aa2d1ab84815bb078399ff7f4d5f9815eef896a0c7e3c049e6fd9932b97096cdb5861425b9d81753d0743212ded1a0fb55a00bf71a46be5ce5e1c8a5cc327b914347d9efcb6cb31ca363b1850d95c7b6c4c3cc6301615ad907318a0c5379d343610fab17eca9c7dc0a5a60658"

func TestKrb5Token_NewAPREQ(t *testing.T) {
	var tkt messages.Ticket
	b, err := hex.DecodeString(testdata.TestVectors["encode_krb5_ticket"])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "encode_krb5_ticket", err)
	}
	err = tkt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "encode_krb5_ticket", err)
	}
	var a types.Authenticator
	//t.Logf("Starting unmarshal tests of %s", v)
	b, err = hex.DecodeString(testdata.TestVectors["encode_krb5_authenticator"])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "encode_krb5_authenticator", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "encode_krb5_authenticator", err)
	}
	var k types.EncryptionKey
	b, err = hex.DecodeString(testdata.TestVectors["encode_krb5_keyblock"])
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "encode_krb5_keyblock", err)
	}
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "encode_krb5_keyblock", err)
	}
}

func TestMechToken_Unmarshal(t *testing.T) {
	b, err := hex.DecodeString(MechToken_Hex)
	if err != nil {
		t.Fatalf("Error decoding MechToken hex: %v", err)
	}
	var mt MechToken
	err = mt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshalling MechToken: %v", err)
	}
}
