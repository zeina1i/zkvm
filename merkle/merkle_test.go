package merkle

import (
	"testing"
)

var data = [][]byte{
	[]byte("alice"),
	[]byte("bob"),
	[]byte("charlie"),
	[]byte("dave"),
}

func TestRootHash(t *testing.T) {
	tree := New(data)
	if tree.RootHash() == nil {
		t.Fatal("root hash should not be nil")
	}
}

func TestRootChangesWhenDataChanges(t *testing.T) {
	tree1 := New(data)
	tree2 := New([][]byte{
		[]byte("alice"),
		[]byte("bob"),
		[]byte("charlie"),
		[]byte("CHANGED"), // dave → CHANGED
	})

	if string(tree1.RootHash()) == string(tree2.RootHash()) {
		t.Fatal("root hash should differ when data changes")
	}
}

func TestGenerateAndVerifyProof(t *testing.T) {
	tree := New(data)

	for i := range data {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("index %d: unexpected error: %v", i, err)
		}

		if !VerifyProof(tree.RootHash(), proof) {
			t.Fatalf("index %d: proof verification failed", i)
		}
	}
}

func TestTamperedProofFails(t *testing.T) {
	tree := New(data)

	proof, _ := tree.GenerateProof(1)
	proof.LeafHash = hashLeaf([]byte("mallory")) // replace leaf with a fake one

	if VerifyProof(tree.RootHash(), proof) {
		t.Fatal("tampered proof should not verify")
	}
}

func TestOddNumberOfLeaves(t *testing.T) {
	oddData := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"), // odd — last node gets duplicated
	}
	tree := New(oddData)

	for i := range oddData {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("index %d: unexpected error: %v", i, err)
		}
		if !VerifyProof(tree.RootHash(), proof) {
			t.Fatalf("index %d: proof verification failed", i)
		}
	}
}

func TestSingleLeaf(t *testing.T) {
	tree := New([][]byte{[]byte("only")})

	proof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyProof(tree.RootHash(), proof) {
		t.Fatal("single leaf proof should verify")
	}
}

func TestOutOfRangeIndex(t *testing.T) {
	tree := New(data)

	_, err := tree.GenerateProof(99)
	if err == nil {
		t.Fatal("expected error for out of range index")
	}
}
