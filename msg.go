package cryptopro

/*
#include "common.h"

static BOOL WINAPI msgUpdateCallback_cgo(
    const void *pvArg,
    BYTE *pbData,
    DWORD cbData,
    BOOL fFinal)
{
	return msgUpdateCallback(pvArg, pbData, cbData, fFinal);
}

static HCERTSTORE openStoreMsg(HCRYPTMSG hMsg) {
	return CertOpenStore(CERT_STORE_PROV_MSG, MY_ENC_TYPE, 0, CERT_STORE_CREATE_NEW_FLAG, hMsg);
}

static CMSG_STREAM_INFO *mkStreamInfo(void *pvArg) {
	CMSG_STREAM_INFO *res = malloc(sizeof(CMSG_STREAM_INFO));
	memset(res, 0, sizeof(CMSG_STREAM_INFO));
	res->cbContent = 0xffffffff;
	res->pfnStreamOutput = &msgUpdateCallback_cgo;
	res->pvArg = pvArg;
	return res;
}

static CMSG_SIGNED_ENCODE_INFO *mkSignedInfo(int n) {
	int i;

	CMSG_SIGNED_ENCODE_INFO *res = malloc(sizeof(CMSG_SIGNED_ENCODE_INFO));
	memset(res, 0, sizeof(CMSG_SIGNED_ENCODE_INFO));
	res->cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);

	res->cSigners = n;
	res->rgSigners = (PCMSG_SIGNER_ENCODE_INFO) malloc(sizeof(CMSG_SIGNER_ENCODE_INFO) * n);
	memset(res->rgSigners, 0, sizeof(CMSG_SIGNER_ENCODE_INFO) * n);

	res->cCertEncoded = n;
	res->rgCertEncoded =  malloc(sizeof(CERT_BLOB) * n);
	memset(res->rgCertEncoded, 0, sizeof(CERT_BLOB) * n);

	return res;
}

static void setSignedInfo(CMSG_SIGNED_ENCODE_INFO *out, int n, HCRYPTPROV hCryptProv, PCCERT_CONTEXT pSignerCert, DWORD dwKeySpec, LPSTR oid) {
	out->rgSigners[n].cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
	out->rgSigners[n].pCertInfo = pSignerCert->pCertInfo;
	out->rgSigners[n].hCryptProv = hCryptProv;
	out->rgSigners[n].dwKeySpec = dwKeySpec;
	out->rgSigners[n].HashAlgorithm.pszObjId = oid;
	out->rgSigners[n].pvHashAuxInfo = NULL;

	out->rgCertEncoded[n].cbData = pSignerCert->cbCertEncoded;
	out->rgCertEncoded[n].pbData = pSignerCert->pbCertEncoded;
}

static void freeSignedInfo(CMSG_SIGNED_ENCODE_INFO *info) {
	free(info->rgCertEncoded);
	free(info->rgSigners);
	free(info);
}

*/
import "C"

import (
	"encoding/asn1"
	"io"
	"io/ioutil"
	"unsafe"

	"github.com/pkg/errors"
)

var (
	GOST_R3411        asn1.ObjectIdentifier = []int{1, 2, 643, 2, 2, 9}
)

type Msg struct {
	hMsg           C.HCRYPTMSG
	src            io.Reader
	dest           io.Writer
	updateCallback func(*C.BYTE, C.DWORD, bool) error
	lastError      error
	data           unsafe.Pointer
	n              int
	maxN           int
	eof            bool
}

type EncodeOptions struct {
	Detached bool
	HashAlg  asn1.ObjectIdentifier
	Signers  []Cert
}

func OpenToDecode(src io.Reader, detachedSig ...[]byte) (*Msg, error) {
	var (
		flags C.DWORD
		si    *C.CMSG_STREAM_INFO
	)

	res := new(Msg)

	if len(detachedSig) > 0 {
		flags = C.CMSG_DETACHED_FLAG
		si = nil
	} else {
		si = C.mkStreamInfo(unsafe.Pointer(res))
		defer C.free(unsafe.Pointer(si))
	}
	res.hMsg = C.CryptMsgOpenToDecode(
		C.MY_ENC_TYPE, // тип закодированного сообщения
		flags,         // флаги
		0,             // поиск данных сообщения
		0,             // криптографический провайдер
		nil,           // информация издателя
		si,            // потоковая информация
	)
	if res.hMsg == nil {
		return nil, errors.New("error opening message for decoding")
	}
	res.src = src
	res.updateCallback = res.onDecode
	for i, p := range detachedSig {
		if !res.update(p, len(p), i == len(detachedSig)-1) {
			return nil, errors.New("error updating message header")
		}
	}
	return res, nil
}

func (msg *Msg) onDecode(pbData *C.BYTE, cbData C.DWORD, fFinal bool) error {
	if int(cbData) > msg.maxN {
		return errors.New("buffer overrun on decoding")
	}
	if pbData != nil && cbData > 0 {
		C.memcpy(msg.data, unsafe.Pointer(pbData), C.size_t(cbData))
		msg.n = int(cbData)
	}
	return nil
}

func (msg *Msg) onEncode(pbData *C.BYTE, cbData C.DWORD, fFinal bool) error {
	msg.n, msg.lastError = msg.dest.Write(C.GoBytes(unsafe.Pointer(pbData), C.int(cbData)))
	return nil
}

//OpenToEncode открывает криптографическое сообщение для закодирования
func OpenToEncode(dest io.Writer, options EncodeOptions) (*Msg, error) {
	var flags C.DWORD

	res := new(Msg)

	if len(options.Signers) == 0 {
		return nil, errors.New("signer certificates list is empty")
	}
	if options.HashAlg == nil {
		options.HashAlg = GOST_R3411
	}
	if options.Detached {
		flags = C.CMSG_DETACHED_FLAG
	}

	si := C.mkStreamInfo(unsafe.Pointer(res))
	defer C.free(unsafe.Pointer(si))

	signedInfo := C.mkSignedInfo(C.int(len(options.Signers)))
	defer C.freeSignedInfo(signedInfo)

	hashOID := C.CString(options.HashAlg.String())
	defer C.free(unsafe.Pointer(hashOID))

	for i, signerCert := range options.Signers {
		var (
			hCryptProv C.HCRYPTPROV
			dwKeySpec  C.DWORD
		)
		if 0 == C.CryptAcquireCertificatePrivateKey(signerCert.pCert, 0, nil, &hCryptProv, &dwKeySpec, nil) {
			return nil, errors.New("error acquiring certificate private key")
		}
		C.setSignedInfo(signedInfo, C.int(i), hCryptProv, signerCert.pCert, dwKeySpec, (*C.CHAR)(hashOID))
	}

	res.hMsg = C.CryptMsgOpenToEncode(
		C.MY_ENC_TYPE,
		flags,
		C.CMSG_SIGNED,
		unsafe.Pointer(signedInfo),
		nil,
		si,
	)
	if res.hMsg == nil {
		return nil, errors.New("error opening message for encoding")
	}
	res.dest = dest
	res.updateCallback = res.onEncode

	return res, nil
}

func (m *Msg) Close() error {
	if m.dest != nil {
		if !m.update([]byte{0}, 0, true) {
			return errors.New("error finalizing message")
		}
	}
	if C.CryptMsgClose(m.hMsg) == 0 {
		return errors.New("error closing message")
	}
	if cl, ok := m.dest.(io.Closer); ok {
		return cl.Close()
	}
	return nil
}

func (m *Msg) update(buf []byte, n int, lastCall bool) bool {
	var lc C.BOOL
	if lastCall {
		lc = C.BOOL(1)
	}
	return C.CryptMsgUpdate(m.hMsg, (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(n), lc) != 0
}

func (m *Msg) Read(buf []byte) (int, error) {
	if m.eof {
		return 0, io.EOF
	}
	nRead, err := m.src.Read(buf)
	if err != nil && err != io.EOF {
		return 0, err
	}

	m.data = unsafe.Pointer(&buf[0])
	m.n = 0
	m.maxN = len(buf)
	m.eof = err == io.EOF

	ok := m.update(buf, nRead, m.eof)
	if !ok {
		return m.n, errors.New("error updating message body")
	}
	return m.n, m.lastError
}

func (m *Msg) Write(buf []byte) (int, error) {
	ok := m.update(buf, len(buf), false)
	if !ok {
		return 0, errors.New("error updating message body")
	}
	return len(buf), m.lastError
}

func (m *Msg) Verify(c Cert) error {
	_, err := ioutil.ReadAll(m)
	if err != nil {
		return err
	}
	if 0 == C.CryptMsgControl(m.hMsg, 0, C.CMSG_CTRL_VERIFY_SIGNATURE, unsafe.Pointer(c.pCert.pCertInfo)) {
		return ErrVerifyingSignature
	}
	return nil
}
