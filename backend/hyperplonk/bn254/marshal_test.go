// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package hyperplonk

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func encodeProof(t testing.TB, p *Proof) []byte {
	var buf bytes.Buffer
	n, err := p.WriteTo(&buf)
	if err != nil || n != int64(buf.Len()) {
		t.Fatalf("WriteTo: n=%d len=%d err=%v", n, buf.Len(), err)
	}
	return buf.Bytes()
}

func sampleProof(t testing.TB) (fixture, *Proof, []byte) {
	f := newLargerFixture(t, UniqueDecoding)
	proof, err := proveWires(f.pk, f.public, f.a, f.b, f.c)
	if err != nil {
		t.Fatal(err)
	}
	return f, proof, encodeProof(t, proof)
}

func TestProofRoundTrip(t *testing.T) {
	f, proof, enc := sampleProof(t)
	var got Proof
	n, err := got.ReadFrom(bytes.NewReader(enc))
	if err != nil || n != int64(len(enc)) {
		t.Fatalf("ReadFrom: n=%d len=%d err=%v", n, len(enc), err)
	}
	if err := Verify(&got, f.vk, f.public); err != nil {
		t.Fatalf("decoded proof rejected: %v", err)
	}
	if !bytes.Equal(encodeProof(t, &got), enc) {
		t.Fatal("re-encoding differs")
	}
	// the encoding is the counted size plus headers and length fields
	counted := proofSize(proof)
	t.Logf("encoded %d bytes, payload counted by proofSize %d bytes, framing %.2f%%", len(enc), counted, 100*float64(len(enc)-counted)/float64(counted))
	if len(enc) < counted {
		t.Fatal("encoding smaller than its payload")
	}
	// trailing bytes are not consumed
	n, err = got.ReadFrom(bytes.NewReader(append(append([]byte(nil), enc...), 1, 2, 3)))
	if err != nil || n != int64(len(enc)) {
		t.Fatalf("with trailing bytes: n=%d err=%v", n, err)
	}
}

func TestKeyRoundTrip(t *testing.T) {
	f := newLargerFixture(t, Johnson)
	var vkBuf, pkBuf bytes.Buffer
	if _, err := f.vk.WriteTo(&vkBuf); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pk.WriteTo(&pkBuf); err != nil {
		t.Fatal(err)
	}
	var vk VerifyingKey
	if n, err := vk.ReadFrom(bytes.NewReader(vkBuf.Bytes())); err != nil || n != int64(vkBuf.Len()) {
		t.Fatalf("vk: n=%d err=%v", n, err)
	}
	if vk != *f.vk {
		t.Fatal("decoded verifying key differs")
	}
	var pk ProvingKey
	if n, err := pk.ReadFrom(bytes.NewReader(pkBuf.Bytes())); err != nil || n != int64(pkBuf.Len()) {
		t.Fatalf("pk: n=%d err=%v", n, err)
	}
	if *pk.Vk != *f.vk {
		t.Fatal("verifying key inside the decoded proving key differs")
	}
	// a proof made with the decoded proving key verifies under the decoded verifying key
	proof, err := proveWires(&pk, f.public, f.a, f.b, f.c)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(proof, &vk, f.public); err != nil {
		t.Fatal(err)
	}
	t.Logf("verifying key %d bytes, proving key %d bytes", vkBuf.Len(), pkBuf.Len())
}

func TestKeyDecodingRejects(t *testing.T) {
	f := newFixture(t, UniqueDecoding)
	var vkBuf, pkBuf bytes.Buffer
	f.vk.WriteTo(&vkBuf)
	f.pk.WriteTo(&pkBuf)
	vkEnc, pkEnc := vkBuf.Bytes(), pkBuf.Bytes()
	mod := func(b []byte, i int, v byte) []byte {
		c := append([]byte(nil), b...)
		c[i] = v
		return c
	}
	bad := map[string][]byte{
		"vk: wrong magic":             mod(vkEnc, 0, 'x'),
		"vk: wrong version":           mod(vkEnc, 4, 9),
		"vk: too many rows":           mod(vkEnc, 8, MaxLogSize+1),
		"vk: unknown regime":          mod(vkEnc, 16, 2),
		"vk: truncated":               vkEnc[:len(vkEnc)-1],
		"vk: too many publics":        mod(vkEnc, 12, 200),
		"pk: a table value changed":   mod(pkEnc, len(vkEnc)+40, pkEnc[len(vkEnc)+40]^1),
		"pk: commitment root changed": mod(pkEnc, len(vkEnc)-1, pkEnc[len(vkEnc)-1]^1),
		"pk: truncated":               pkEnc[:len(pkEnc)-1],
	}
	for name, enc := range bad {
		var err error
		if name[:2] == "vk" {
			_, err = new(VerifyingKey).ReadFrom(bytes.NewReader(enc))
		} else {
			_, err = new(ProvingKey).ReadFrom(bytes.NewReader(enc))
		}
		if !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// a changed circuit hash changes the digest: proofs no longer verify
	var vk VerifyingKey
	if _, err := vk.ReadFrom(bytes.NewReader(mod(vkEnc, 20, vkEnc[20]^1))); err != nil {
		t.Fatal(err)
	}
	proof, _ := proveWires(f.pk, f.public, f.a, f.b, f.c)
	if Verify(proof, &vk, f.public) == nil {
		t.Fatal("proof verified under a key with another circuit hash")
	}
}

// Every strict prefix of a proof fails to decode.
func TestProofTruncation(t *testing.T) {
	_, _, enc := sampleProof(t)
	rng := rand.New(rand.NewSource(1))
	cuts := []int{0, 1, 4, 5, 6, len(enc) - 1, len(enc) - 32, len(enc) - 33}
	for range 300 {
		cuts = append(cuts, rng.Intn(len(enc)))
	}
	for _, c := range cuts {
		if _, err := new(Proof).ReadFrom(bytes.NewReader(enc[:c])); !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("prefix of %d bytes: got %v", c, err)
		}
	}
}

// A proof with one bit flipped either fails to decode or fails to verify,
// and never panics. Flips are spread over the whole encoding, and every byte
// of the first 2 KiB (headers, PIOP messages, values) is covered.
func TestProofBitFlips(t *testing.T) {
	f, _, enc := sampleProof(t)
	rng := rand.New(rand.NewSource(2))
	var positions []int
	for i := 0; i < 2048 && i < len(enc); i++ {
		positions = append(positions, i)
	}
	for range 1500 {
		positions = append(positions, rng.Intn(len(enc)))
	}
	decoded, rejectedByDecoder := 0, 0
	for _, pos := range positions {
		mut := append([]byte(nil), enc...)
		mut[pos] ^= 1 << uint(rng.Intn(8))
		var p Proof
		if _, err := p.ReadFrom(bytes.NewReader(mut)); err != nil {
			rejectedByDecoder++
			continue
		}
		decoded++
		if err := Verify(&p, f.vk, f.public); err == nil {
			t.Fatalf("bit flip at byte %d accepted", pos)
		}
	}
	t.Logf("%d flips: %d rejected by the decoder, %d decoded and rejected by Verify", len(positions), rejectedByDecoder, decoded)
}

// Non-canonical field elements are rejected: each value has one encoding.
func TestNonCanonicalElement(t *testing.T) {
	_, _, enc := sampleProof(t)
	mut := append([]byte(nil), enc...)
	// the first field element is WOOD, after magic, version and the w root
	copy(mut[5+32:], bytes.Repeat([]byte{0xff}, fr.Bytes))
	if _, err := new(Proof).ReadFrom(bytes.NewReader(mut)); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("got %v", err)
	}
}

// A few bytes must not make the decoder allocate much: every length is
// bounded and data is read before the next allocation.
func TestHugeLengthsAreRejected(t *testing.T) {
	_, _, enc := sampleProof(t)
	// the first length field is the number of gate sumcheck rounds
	off := 5 + 32 + 32
	mut := append([]byte(nil), enc[:off+4]...)
	copy(mut[off:], []byte{0xff, 0xff, 0xff, 0xff})
	if _, err := new(Proof).ReadFrom(bytes.NewReader(mut)); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("got %v", err)
	}
}

// FuzzProofReadFrom: decoding and verifying arbitrary bytes never panics and
// never accepts anything but the genuine proof.
func FuzzProofReadFrom(f *testing.F) {
	fx := newFixture(f, UniqueDecoding)
	proof, err := proveWires(fx.pk, fx.public, fx.a, fx.b, fx.c)
	if err != nil {
		f.Fatal(err)
	}
	var buf bytes.Buffer
	proof.WriteTo(&buf)
	genuine := buf.Bytes()
	f.Add(genuine)
	f.Add(genuine[:len(genuine)/2])
	f.Add([]byte("ghpP\x01"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var p Proof
		if _, err := p.ReadFrom(bytes.NewReader(data)); err != nil {
			return
		}
		if Verify(&p, fx.vk, fx.public) == nil {
			var again bytes.Buffer
			p.WriteTo(&again)
			if !bytes.Equal(again.Bytes(), genuine) {
				t.Fatal("a proof other than the genuine one was accepted")
			}
		}
	})
}
