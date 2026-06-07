package schnorr

import (
	"crypto/elliptic"
	"math/big"
)

// InteractiveProver holds the prover's state across the 3 rounds.
type InteractiveProver struct {
	keyPair *KeyPair
	k       *big.Int // secret nonce, must not be reused
	R       *Point   // commitment, sent to verifier in round 1
}

// InteractiveVerifier holds the verifier's state across the 3 rounds.
type InteractiveVerifier struct {
	publicKey *Point
	message   []byte
	e         *big.Int // challenge sent to prover in round 2
}

func NewInteractiveProver(keyPair *KeyPair, kEntropy []byte) *InteractiveProver {
	curve := elliptic.P256()

	k := new(big.Int).SetBytes(kEntropy)
	k.Mod(k, curve.Params().N)

	rX, rY := curve.ScalarBaseMult(k.Bytes())

	return &InteractiveProver{
		keyPair: keyPair,
		k:       k,
		R:       &Point{X: rX, Y: rY},
	}
}

func NewInteractiveVerifier(publicKey *Point, message []byte) *InteractiveVerifier {
	return &InteractiveVerifier{publicKey: publicKey, message: message}
}

// --- Round 1: Prover sends commitment R ---

func (p *InteractiveProver) Commit() *Point {
	return p.R
}

// --- Round 2: Verifier receives R, sends back a random challenge e ---

func (v *InteractiveVerifier) Challenge(R *Point, eEntropy []byte) *big.Int {
	curve := elliptic.P256()

	// In a real protocol, e would be uniformly random.
	// We accept eEntropy here to keep things deterministic in tests.
	e := new(big.Int).SetBytes(eEntropy)
	e.Mod(e, curve.Params().N)

	v.e = e
	return e
}

// --- Round 3: Prover receives challenge, sends response s ---

func (p *InteractiveProver) Respond(e *big.Int) *big.Int {
	curve := elliptic.P256()

	// s = k + e*x mod n
	s := new(big.Int).Mul(e, p.keyPair.PrivateKey)
	s.Add(s, p.k)
	s.Mod(s, curve.Params().N)

	return s
}

// --- Verifier checks: s*G == R + e*P ---

func (v *InteractiveVerifier) Verify(R *Point, s *big.Int) bool {
	curve := elliptic.P256()

	// left: s*G
	leftX, leftY := curve.ScalarBaseMult(s.Bytes())

	// right: R + e*P
	ePx, ePy := curve.ScalarMult(v.publicKey.X, v.publicKey.Y, v.e.Bytes())
	rightX, rightY := curve.Add(R.X, R.Y, ePx, ePy)

	return leftX.Cmp(rightX) == 0 && leftY.Cmp(rightY) == 0
}
