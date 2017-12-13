package lmots

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSecurityString(t *testing.T) {
	secStr := newSecurityString()
	// no I included
	expectedSecStr := []byte{
		0x12, 0x34, 0x56, 0x78, // r or q
		0x9a, 0xbc, // domain separation field
		0x0d, // number of iterations when evaluating Winternitz chain
	}
	offset := 0

	secStr.setNodeIdx(0x12345678)
	rq := []byte(secStr)[rq_offset:dsf_offset]
	if !bytes.Equal(rq, expectedSecStr[offset:(offset+4)]) {
		t.Fatalf("want %x, got %x", expectedSecStr[offset:(offset+4)], rq)
	}
	offset += 4

	secStr.setDSF(0x9abc)
	dsf := []byte(secStr)[dsf_offset:wtn_chain_num_iter_offset]
	if !bytes.Equal(dsf, expectedSecStr[offset:(offset+2)]) {
		t.Fatalf("want %x, got %x", expectedSecStr[offset:(offset+2)], dsf)
	}
	offset += 2

	secStr.setWtnChainNumItr(expectedSecStr[offset])
	fmt.Println(len(secStr), wtn_chain_num_iter_offset)
	numItr := []byte(secStr)[wtn_chain_num_iter_offset]
	if numItr != expectedSecStr[offset] {
		t.Fatalf("want %x, got %x", expectedSecStr[offset], numItr)
	}

	ss := []byte(secStr)
	if !bytes.Equal(expectedSecStr, ss) {
		t.Fatalf("want %x, got %x", expectedSecStr, ss)
	}
}
