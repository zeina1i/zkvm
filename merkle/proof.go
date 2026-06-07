package merkle

import (
	"bytes"
	"errors"
)

// ProofNode is one sibling hash along the path from a leaf to the root.
type ProofNode struct {
	Hash []byte
	Left bool // true if this sibling is on the LEFT side
}

// Proof holds everything needed to verify a leaf is in the tree.
type Proof struct {
	LeafHash []byte
	Siblings []ProofNode
}

// GenerateProof returns a Merkle proof for the leaf at the given index.
func (t *Tree) GenerateProof(index int) (*Proof, error) {
	if index < 0 || index >= len(t.Leaves) {
		return nil, errors.New("index out of range")
	}

	proof := &Proof{LeafHash: t.Leaves[index].Hash}
	collectSiblings(t.Root, index, len(t.Leaves), proof)

	// collectSiblings walks top-down (root → leaf), but VerifyProof
	// needs to apply siblings bottom-up (leaf → root), so reverse.
	for i, j := 0, len(proof.Siblings)-1; i < j; i, j = i+1, j-1 {
		proof.Siblings[i], proof.Siblings[j] = proof.Siblings[j], proof.Siblings[i]
	}

	return proof, nil
}

// collectSiblings walks the tree top-down and collects sibling hashes along the path to the target leaf.
func collectSiblings(node *Node, target, size int, proof *Proof) {
	if node.Left == nil && node.Right == nil {
		return // reached a leaf
	}

	if size%2 != 0 {
		size++ // account for the duplicated node
	}

	mid := size / 2
	if target < mid {
		// target is in the left subtree, sibling is on the right
		proof.Siblings = append(proof.Siblings, ProofNode{
			Hash: node.Right.Hash,
			Left: false,
		})
		collectSiblings(node.Left, target, mid, proof)
	} else {
		// target is in the right subtree, sibling is on the left
		proof.Siblings = append(proof.Siblings, ProofNode{
			Hash: node.Left.Hash,
			Left: true,
		})
		collectSiblings(node.Right, target-mid, size-mid, proof)
	}
}

// VerifyProof checks that a proof is valid against the given root hash.
func VerifyProof(rootHash []byte, proof *Proof) bool {
	current := proof.LeafHash

	for _, sibling := range proof.Siblings {
		if sibling.Left {
			current = hashParent(sibling.Hash, current)
		} else {
			current = hashParent(current, sibling.Hash)
		}
	}

	return bytes.Equal(current, rootHash)
}
