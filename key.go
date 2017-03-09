package cryptopro

//#include "common.h"
import "C"
import "github.com/pkg/errors"

type KeyFlag C.DWORD

const (
	KeyArchivable KeyFlag = C.CRYPT_ARCHIVABLE
	KeyExportable KeyFlag = C.CRYPT_EXPORTABLE
)

type KeyPairId C.DWORD

const (
	AtKeyExchange KeyPairId = C.AT_KEYEXCHANGE
	AtSignature   KeyPairId = C.AT_SIGNATURE
)

type Key struct {
	hKey C.HCRYPTKEY
}

func (ctx Ctx) Key(at KeyPairId) (Key, error) {
	res := Key{}
	if C.CryptGetUserKey(ctx.hProv, C.DWORD(at), &res.hKey) == 0 {
		return res, errors.New("error getting key for container")
	}
	return res, nil
}

func (ctx Ctx) GenKey(at KeyPairId, flags KeyFlag) (Key, error) {
	res := Key{}
	if C.CryptGenKey(ctx.hProv, C.ALG_ID(at), C.DWORD(flags), &res.hKey) == 0 {
		return res, errors.New("error creating key for container")
	}
	return res, nil
}

func (key Key) Close() error {
	if C.CryptDestroyKey(key.hKey) == 0 {
		return errors.New("error releasing key")
	}
	return nil
}
