// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package whir

import (
	"crypto/sha256"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/consensys/gnark/backend/hyperplonk/internal/par"
)

// Digest is a sha256 output.
type Digest = [sha256.Size]byte

// A leaf and an inner node are hashed with different prefixes, so a leaf can
// never be presented as an inner node (second-preimage resistance of the
// tree for a fixed depth and leaf size, which the verifier enforces).
//
// The prefixes also differ from the three the transcript uses (0x00, 0x01,
// 0x02), so that tree hashing, transcript absorption and challenge derivation
// are evaluations of the hash function on disjoint sets of inputs. BCS
// (ePrint 2016/116, §6) separates only the challenge oracle from the rest;
// this is stricter.
const (
	prefixLeaf = 0x10
	prefixNode = 0x11
)

func hashLeaf(vals []fr.Element) Digest {
	h := sha256.New()
	h.Write([]byte{prefixLeaf})
	for i := range vals {
		b := vals[i].Bytes()
		h.Write(b[:])
	}
	var d Digest
	h.Sum(d[:0])
	return d
}

func hashNode(l, r Digest) Digest {
	h := sha256.New()
	h.Write([]byte{prefixNode})
	h.Write(l[:])
	h.Write(r[:])
	var d Digest
	h.Sum(d[:0])
	return d
}

// merkleTree stores all levels; levels[0] are the leaf hashes.
type merkleTree struct {
	levels [][]Digest
}

// newMerkleTree builds a tree over a power-of-two number of leaves.
func newMerkleTree(leaves [][]fr.Element) *merkleTree {
	level := make([]Digest, len(leaves))
	par.Range(len(leaves), 256, func(start, end int) {
		for i := start; i < end; i++ {
			level[i] = hashLeaf(leaves[i])
		}
	})
	t := &merkleTree{levels: [][]Digest{level}}
	for len(level) > 1 {
		next := make([]Digest, len(level)/2)
		cur := level
		par.Range(len(next), 1024, func(start, end int) {
			for i := start; i < end; i++ {
				next[i] = hashNode(cur[2*i], cur[2*i+1])
			}
		})
		t.levels = append(t.levels, next)
		level = next
	}
	return t
}

func (t *merkleTree) root() Digest { return t.levels[len(t.levels)-1][0] }

// path returns the sibling hashes from leaf idx up to the root.
func (t *merkleTree) path(idx int) []Digest {
	p := make([]Digest, 0, len(t.levels)-1)
	for _, level := range t.levels[:len(t.levels)-1] {
		p = append(p, level[idx^1])
		idx >>= 1
	}
	return p
}

// verifyPath checks that leaf sits at position idx of a tree with nbLeaves
// leaves and the given root.
func verifyPath(root Digest, nbLeaves, idx int, leaf []fr.Element, path []Digest) bool {
	depth := 0
	for 1<<depth < nbLeaves {
		depth++
	}
	if len(path) != depth || idx < 0 || idx >= nbLeaves {
		return false
	}
	cur := hashLeaf(leaf)
	for _, sib := range path {
		if idx&1 == 0 {
			cur = hashNode(cur, sib)
		} else {
			cur = hashNode(sib, cur)
		}
		idx >>= 1
	}
	return cur == root
}
