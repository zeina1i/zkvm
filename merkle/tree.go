package merkle

import "crypto/sha256"

type Node struct {
	Left  *Node
	Right *Node
	Hash  []byte
}

type Tree struct {
	Root   *Node
	Leaves []*Node
}

// New builds a Merkle tree from raw data blocks.
func New(data [][]byte) *Tree {
	if len(data) == 0 {
		return &Tree{}
	}

	leaves := make([]*Node, len(data))
	for i, d := range data {
		leaves[i] = &Node{Hash: hashLeaf(d)}
	}

	root := buildLevel(leaves)
	return &Tree{Root: root, Leaves: leaves}
}

// RootHash returns the root hash of the tree.
func (t *Tree) RootHash() []byte {
	if t.Root == nil {
		return nil
	}
	return t.Root.Hash
}

// hashLeaf hashes a leaf node: SHA256(0x00 || data)
// The 0x00 prefix prevents second-preimage attacks.
func hashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// hashParent hashes an internal node: SHA256(0x01 || left || right)
// The 0x01 prefix distinguishes internal nodes from leaves.
func hashParent(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// buildLevel reduces a slice of nodes up to a single root node.
func buildLevel(nodes []*Node) *Node {
	if len(nodes) == 1 {
		return nodes[0]
	}

	if len(nodes)%2 != 0 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}

	parents := make([]*Node, len(nodes)/2)
	for i := 0; i < len(nodes); i += 2 {
		left, right := nodes[i], nodes[i+1]
		parents[i/2] = &Node{
			Left:  left,
			Right: right,
			Hash:  hashParent(left.Hash, right.Hash),
		}
	}

	return buildLevel(parents)
}
