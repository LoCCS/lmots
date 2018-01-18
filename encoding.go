package lmots

import (
	"bytes"
	"encoding/gob"
)

type pkEx struct {
	Opts *LMOpts
	K    HashType
}

func (pk PublicKey) GobEncode() ([]byte, error) {
	pkC := &pkEx{
		Opts: pk.LMOpts,
		K:    pk.K,
	}

	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(pkC); nil != err {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (pk *PublicKey) GobDecode(data []byte) error {
	pkC := new(pkEx)

	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(pkC); nil != err {
		return err
	}

	pk.LMOpts = pkC.Opts
	pk.K = pkC.K

	return nil
}

type sigEx struct {
	Typecode [4]byte
	C        []byte
	Sigma    []HashType
}

func (sig Sig) GobEncode() ([]byte, error) {
	sigC := &sigEx{
		Typecode: sig.typecode,
		C:        sig.C,
		Sigma:    sig.sigma,
	}

	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(sigC); nil != err {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (sig *Sig) GobDecode(data []byte) error {
	sigC := new(sigEx)

	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(sigC); nil != err {
		return err
	}

	sig.typecode = sigC.Typecode
	sig.C = sigC.C
	sig.sigma = sigC.Sigma

	return nil
}
