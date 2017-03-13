package test

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"testing"

	"github.com/l-vitaly/cryptopro"
	"github.com/l-vitaly/gounit"
)

var certData = `
MIIC/DCCAeagAwIBAgIRAOFquydyZU9tgXgQd5f2h6IwCwYJKoZIhvcNAQELMBIx
EDAOBgNVBAoTB0FjbWUgQ28wHhcNMTUwNzA1MDcyNzE2WhcNMTYwNzA0MDcyNzE2
WjASMRAwDgYDVQQKEwdBY21lIENvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAxGD/bLOlmcichuYV2sjPB8yIxW4ULhqhqyCKf0S0lUTdY0kUwuAOVO8w
3UWJX0QaFJpP8k0jY+wasyWvaqeiKvNtnNuvwjLrClvzwtnjtvgTYQPUbUM8JAsp
P/7FrOd41uL5jqTs0cfN/zxVQq5dePclYqfOQsbpNulHP7vXuyxMDl1yeeHK/S2T
3O8Fx7SErztjs2ThJbrvhZgrmdptOuAmR45oSyTnEpeiPysGlZOm4ntvFBXXjWi3
xeUClxHymlFbjA2Yk932PLuvcunAM5ihPZBknxUrZIriq6Vhu60L+L23jyxdP4/o
I2xlOzhUYi22YirYPTf0iNekTPA7bwIDAQABo1EwTzAOBgNVHQ8BAf8EBAMCAKAw
EwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAaBgNVHREEEzARgg9U
ZXN0R29DcnlwdG9BUEkwCwYJKoZIhvcNAQELA4IBAQB44i6Cjt1soIYcrXX/+BhM
/jEVxuYUY9VXEJ5RR+hxEhdPueB0i0b4NTKe417PA5jVHN9YeV6gKBXDMaAnN/E1
o5l+w7WxM03GGklH6TtH7aYsCIH8xUA5AkXB0ZNDLyDeMnq1sIzD/Z+ugIpMLuvt
VYFkQ2KwFCaqBJkq2Un9I3bUzXU4X9umubD4DUd1CSH1uRyQQfsnJjz8TWeS9nVe
Fy/OfGEaF8zewD+iSsmob52ifRG7qYcN1rEsyfHpQ33oooB/I8s9Nil9WatEpZNC
Sp4EAT/s6eUCx00m2uS2SJ83n7XHWr0hKxEtISL9tAA1fzwvT1eswO2IdKSBg47K
`

func TestCryptopro(t *testing.T) {
	u := gounit.New(t)
	cert := getCert()
	u.AssertNotNil(cert, "")
	u.AssertNotError(cert.Close(), "")
}

func TestCerts(t *testing.T) {
	u := gounit.New(t)

	store, err := cryptopro.SystemStore("MY")
	u.AssertNotError(err, "")
	defer store.Close()

	for _, c := range store.Certs() {
		t.Log(c.ThumbPrint())
	}

}

func TestMsgEncode(t *testing.T) {
	u := gounit.New(t)

	store, err := cryptopro.SystemStore("MY")
	u.AssertNotError(err, "")
	defer store.Close()

	crt, err := store.GetBySHA1("5f08160e7dca8db7b8b3fd1b055a6c4300c37ba6")
	u.AssertNotError(err, "")
	defer crt.Close()

	data := bytes.NewBufferString(`<bki_request version="3.4" partnerid="90J">
    <request num="1">
        <private>
            <lastname>СЕРГЕЕВ</lastname>
            <firstname>СЕРГЕЙ</firstname>
            <middlename>СЕРГЕЕВИЧ</middlename>
            <birthday>20.01.1975</birthday>
            <birthplace>МОСКВА</birthplace>
            <doc>
                <doctype>1</doctype>
                <docno>2000000000</docno>
                <docdate>01.01.2016</docdate>
                <docplace>ОВД УЛЬЯНОВСКА</docplace>
            </doc>
            <gender>1</gender>
        </private>
        <reason>1</reason>
        <application>
            <consent>1</consent>
            <consentdate>03.03.2017</consentdate>
            <consentenddate>04.03.2017</consentenddate>
            <admcode_inform>1</admcode_inform>
        </application>
        <addr_reg>
            <index>000000</index>
            <country>RU</country>
            <city>МОСКВА</city>
            <street>6 КВАРТАЛ</street>
            <house>17</house>
            <flat>48</flat>
        </addr_reg>
        <addr_fact>
            <index>000000</index>
            <country>RU</country>
            <city>МОСКВА</city>
            <street>6 КВАРТАЛ</street>
            <house>17</house>
            <flat>48</flat>
        </addr_fact>
        <type>30033</type>
    </request>
</bki_request>`)
	dest := new(bytes.Buffer)
	msg, err := cryptopro.OpenToEncode(dest, cryptopro.EncodeOptions{
		Signers: []cryptopro.Cert{crt},
	})
	u.AssertNotError(err, "")

	_, err = data.WriteTo(msg)
	u.AssertNotError(err, "")
	u.AssertNotError(msg.Close(), "")
	u.AssertGreaterThan(0, len(dest.Bytes()), "")

	o, err := os.Create("./logical2.cms")
	defer o.Close()

	_, err = io.Copy(o, dest)
	u.AssertNotError(err, gounit.EmptyMessage)

	f, err := os.Open("./logical2.cms")
	u.AssertNotError(err, gounit.EmptyMessage)
	defer f.Close()

	msg2, err := cryptopro.OpenToDecode(f)
	u.AssertNotError(err, gounit.EmptyMessage)

	o2, err := os.Create("./logical2.bin")
	u.AssertNotError(err, gounit.EmptyMessage)
	defer o2.Close()

	n, err := io.Copy(o2, msg2)
	u.AssertNotError(err, gounit.EmptyMessage)
	u.AssertGreaterThan(0, int(n), gounit.EmptyMessage)

	err = msg2.Verify(crt)
	u.AssertNotError(err, gounit.EmptyMessage)

	msg2.Close()
}

func getCert() cryptopro.Cert {
	data, _ := base64.StdEncoding.DecodeString(certData)
	crt, err := cryptopro.ParseCert(data)
	if err != nil {
		panic(err)
	}
	return crt
}
