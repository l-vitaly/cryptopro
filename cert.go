package cryptopro

//#include "common.h"
import "C"

import (
	"encoding/hex"
	"unsafe"

	"github.com/pkg/errors"
)

var (
	ErrCreatingCertificateCtx = errors.New("error a new certificate could not be created")
)

type Cert struct {
	pCert C.PCCERT_CONTEXT
}

func ParseCert(buf []byte) (Cert, error) {
	bufBytes := C.CBytes(buf)
	defer C.free(bufBytes)

	var res Cert
	res.pCert = C.CertCreateCertificateContext(C.MY_ENC_TYPE, (*C.BYTE)(bufBytes), C.DWORD(len(buf)))
	if res.pCert == nil {
		return Cert{}, ErrCreatingCertificateCtx

	}
	return res, nil
}

func (c Cert) Close() error {
	if C.CertFreeCertificateContext(c.pCert) == 0 {
		return errors.New("error releasing certificate context")
	}
	return nil
}

type CertPropertyId C.DWORD

const (
	CertHashProp          CertPropertyId = C.CERT_HASH_PROP_ID
	CertKeyIdentifierProp CertPropertyId = C.CERT_KEY_IDENTIFIER_PROP_ID
	CertProvInfoProp      CertPropertyId = C.CERT_KEY_PROV_INFO_PROP_ID
)

func (c Cert) GetProperty(propId CertPropertyId) ([]byte, error) {
	var slen C.DWORD
	var res []byte
	if C.CertGetCertificateContextProperty(c.pCert, C.DWORD(propId), nil, &slen) == 0 {
		return res, errors.New("error getting cert context property size")
	}
	res = make([]byte, slen)
	if C.CertGetCertificateContextProperty(c.pCert, C.DWORD(propId), unsafe.Pointer(&res[0]), &slen) == 0 {
		return res, errors.New("error getting cert context property body")
	}
	return res, nil
}

func (c Cert) ThumbPrint() (string, error) {
	thumb, err := c.GetProperty(CertHashProp)
	return hex.EncodeToString(thumb), err
}

func (c Cert) MustThumbPrint() string {
	if thumb, err := c.ThumbPrint(); err != nil {
		panic(err)
	} else {
		return thumb
	}
}

func (c Cert) SubjectId() (string, error) {
	thumb, err := c.GetProperty(CertKeyIdentifierProp)
	return hex.EncodeToString(thumb), err
}

func (c Cert) MustSubjectId() string {
	if subj, err := c.SubjectId(); err != nil {
		panic(err)
	} else {
		return subj
	}
}

func (c Cert) Bytes() []byte {
	return C.GoBytes(unsafe.Pointer(c.pCert.pbCertEncoded), C.int(c.pCert.cbCertEncoded))
}
