package cryptopro

/*
#include "common.h"

HCERTSTORE openStoreMem() {
	return CertOpenStore(CERT_STORE_PROV_MEMORY, MY_ENC_TYPE, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
}

HCERTSTORE openStoreSystem(HCRYPTPROV hProv, CHAR *proto) {
	return CertOpenStore(
		CERT_STORE_PROV_SYSTEM_A,          // The store provider type
		0,                               // The encoding type is
		// not needed
		hProv,                            // Use the default HCRYPTPROV
		// Set the store location in a
		// registry location
		CERT_STORE_NO_CRYPT_RELEASE_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
		proto                            // The store name as a Unicode
		// string
	);
}

*/
import "C"

import (
	"encoding/hex"
	"unsafe"

	"github.com/pkg/errors"
)

type CertStore struct {
	hStore C.HCERTSTORE
}

func MemoryStore() (CertStore, error) {
	res := CertStore{}
	res.hStore = C.openStoreMem()
	if res.hStore == C.HCERTSTORE(nil) {
		return res, errors.New("error creating memory cert store")
	}
	return res, nil
}

func SystemStore(name string) (CertStore, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	res := CertStore{}
	res.hStore = C.openStoreSystem(C.HCRYPTPROV(0), (*C.CHAR)(cName))
	if res.hStore == C.HCERTSTORE(nil) {
		return res, errors.New("error getting system cert store")
	}
	return res, nil
}

func (c Ctx) CertStore(name string) (CertStore, error) {
	cName := charPtr(name)
	defer freePtr(cName)

	res := CertStore{}
	res.hStore = C.openStoreSystem(c.hProv, cName)
	if res.hStore == nil {
		return res, errors.New("error getting system cert store")
	}
	return res, nil
}

func (s CertStore) Close() error {
	if C.CertCloseStore(s.hStore, C.CERT_CLOSE_STORE_CHECK_FLAG) == 0 {
		return errors.New("error closing cert store")
	}
	return nil
}

func (s CertStore) findCerts(findType C.DWORD, findPara unsafe.Pointer) []Cert {
	var res []Cert

	for pCert := C.CertFindCertificateInStore(s.hStore, C.MY_ENC_TYPE, 0, findType, findPara, nil); pCert != nil; pCert = C.CertFindCertificateInStore(s.hStore, C.MY_ENC_TYPE, 0, findType, findPara, pCert) {
		pCertDup := C.CertDuplicateCertificateContext(pCert)
		res = append(res, Cert{pCertDup})
	}
	return res
}

func (s CertStore) getCert(findType C.DWORD, findPara unsafe.Pointer) C.PCCERT_CONTEXT {
	return C.CertFindCertificateInStore(s.hStore, C.MY_ENC_TYPE, 0, findType, findPara, nil)
}

func (s CertStore) FindBySubject(subject string) []Cert {
	cSubject := unsafe.Pointer(C.CString(subject))
	defer C.free(cSubject)
	return s.findCerts(C.CERT_FIND_SUBJECT_STR_A, cSubject)
}

func (s CertStore) FindByThumb(thumb string) []Cert {
	bThumb, err := hex.DecodeString(thumb)
	if err != nil {
		return nil
	}
	var hashBlob C.CRYPT_HASH_BLOB
	hashBlob.cbData = C.DWORD(len(bThumb))
	bThumbPtr := C.CBytes(bThumb)
	defer C.free(bThumbPtr)
	hashBlob.pbData = (*C.BYTE)(bThumbPtr)
	return s.findCerts(C.CERT_FIND_HASH, unsafe.Pointer(&hashBlob))
}

func (s CertStore) FindBySubjectId(thumb string) []Cert {
	bThumb, err := hex.DecodeString(thumb)
	if err != nil {
		return nil
	}
	var hashBlob C.CRYPT_HASH_BLOB
	hashBlob.cbData = C.DWORD(len(bThumb))
	bThumbPtr := C.CBytes(bThumb)
	defer C.free(bThumbPtr)
	hashBlob.pbData = (*C.BYTE)(bThumbPtr)
	return s.findCerts(C.CERT_FIND_KEY_IDENTIFIER, unsafe.Pointer(&hashBlob))
}

func (s CertStore) GetByThumb(thumb string) (Cert, error) {
	res := Cert{}

	bThumb, err := hex.DecodeString(thumb)
	if err != nil {
		return res, err
	}
	var hashBlob C.CRYPT_HASH_BLOB
	hashBlob.cbData = C.DWORD(len(bThumb))
	bThumbPtr := C.CBytes(bThumb)
	defer C.free(bThumbPtr)
	hashBlob.pbData = (*C.BYTE)(bThumbPtr)

	if res.pCert = s.getCert(C.CERT_FIND_HASH, unsafe.Pointer(&hashBlob)); res.pCert == nil {
		return res, errors.New("error looking up certificate by thumb")
	}
	return res, nil
}

func (s CertStore) GetBySubjectId(keyId string) (Cert, error) {
	res := Cert{}

	bThumb, err := hex.DecodeString(keyId)
	if err != nil {
		return res, err
	}
	var hashBlob C.CRYPT_HASH_BLOB
	hashBlob.cbData = C.DWORD(len(bThumb))
	bThumbPtr := C.CBytes(bThumb)
	defer C.free(bThumbPtr)

	hashBlob.pbData = (*C.BYTE)(bThumbPtr)
	if res.pCert = s.getCert(C.CERT_FIND_KEY_IDENTIFIER, unsafe.Pointer(&hashBlob)); res.pCert == nil {
		return res, errors.New("error looking up certificate by subject key id")
	}
	return res, nil
}

func (s CertStore) GetBySubject(subject string) (Cert, error) {
	res := Cert{}
	cSubject := unsafe.Pointer(C.CString(subject))
	defer C.free(cSubject)

	if res.pCert = s.getCert(C.CERT_FIND_SUBJECT_STR_A, cSubject); res.pCert == nil {
		return res, errors.New("error looking up certificate by subject string")
	}
	return res, nil
}

func (s CertStore) Add(cert Cert) error {
	if C.CertAddCertificateContextToStore(s.hStore, cert.pCert, C.CERT_STORE_ADD_REPLACE_EXISTING, nil) == 0 {
		return errors.New("couldn't add certificate to store")
	}
	return nil
}

func (s CertStore) Certs() []Cert {
	var res []Cert
	for pCert := C.CertEnumCertificatesInStore(s.hStore, nil); pCert != nil; pCert = C.CertEnumCertificatesInStore(s.hStore, pCert) {
		pCertDup := C.CertDuplicateCertificateContext(pCert)
		res = append(res, Cert{pCertDup})
	}
	return res
}
