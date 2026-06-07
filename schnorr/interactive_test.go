package schnorr

import (
	"testing"
)

// TestInteractiveProtocol shows the 3-round interactive Schnorr protocol.
//
// Round 1: Prover sends commitment R
// Round 2: Verifier sends random challenge e
// Round 3: Prover sends response s
// Verify: s*G == R + e*P
func TestInteractiveProtocol(t *testing.T) {
	impl := Impl{}
	msg := []byte("hello")

	kp, _ := impl.GenerateKeyPair(randomEntropy(t, 32))

	prover := NewInteractiveProver(kp, randomEntropy(t, 32))
	verifier := NewInteractiveVerifier(kp.PublicKey, msg)

	R := prover.Commit()                             // round 1
	e := verifier.Challenge(R, randomEntropy(t, 32)) // round 2
	s := prover.Respond(e)                           // round 3

	if !verifier.Verify(R, s) {
		t.Fatal("interactive proof should verify")
	}
}

// TestFiatShamirVsInteractive shows that Fiat-Shamir produces the same
// verification equation — just with the challenge derived from a hash
// instead of from the verifier.
//
// Both protocols check: s*G == R + e*P
// The only difference is where e comes from:
//
//	Interactive:   e = verifier's random value
//	Fiat-Shamir:   e = SHA256(R || P || message)
func TestFiatShamirVsInteractive(t *testing.T) {
	impl := Impl{}
	msg := []byte("hello")
	kEntropy := randomEntropy(t, 32)

	kp, _ := impl.GenerateKeyPair(randomEntropy(t, 32))

	// --- Interactive ---
	prover := NewInteractiveProver(kp, kEntropy)
	verifier := NewInteractiveVerifier(kp.PublicKey, msg)
	R := prover.Commit()
	e := verifier.Challenge(R, randomEntropy(t, 32)) // random e from verifier
	s := prover.Respond(e)
	interactiveResult := verifier.Verify(R, s)

	// --- Non-interactive (Fiat-Shamir) ---
	sig, _ := impl.Sign(kp, msg, kEntropy)
	fiatShamirResult := impl.Verify(kp.PublicKey, msg, sig)

	if !interactiveResult {
		t.Fatal("interactive proof should verify")
	}
	if !fiatShamirResult {
		t.Fatal("fiat-shamir proof should verify")
	}

	// Both verify using the same equation: s*G == R + e*P
	// The only difference is how e was produced.
}

// TestInteractiveWrongChallenge shows that a tampered challenge breaks the proof.
func TestInteractiveWrongChallenge(t *testing.T) {
	impl := Impl{}
	msg := []byte("hello")

	kp, _ := impl.GenerateKeyPair(randomEntropy(t, 32))

	prover := NewInteractiveProver(kp, randomEntropy(t, 32))
	verifier := NewInteractiveVerifier(kp.PublicKey, msg)

	R := prover.Commit()
	e := verifier.Challenge(R, randomEntropy(t, 32))

	// Prover responds to e, but verifier secretly used a different e
	fakeE := verifier.Challenge(R, randomEntropy(t, 32)) // different challenge
	_ = fakeE

	s := prover.Respond(e) // prover responds to original e

	// Verifier now checks with the fake e — should fail
	if verifier.Verify(R, s) {
		t.Fatal("proof with mismatched challenge should not verify")
	}
}
