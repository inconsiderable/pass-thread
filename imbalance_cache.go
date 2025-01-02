package passthread

import (
	"golang.org/x/crypto/ed25519"
)

// ImbalanceCache maintains a partial unconfirmed view of the ledger.
// It's used by Ledger when (dis-)connecting passes and by ConsiderationQueueMemory
// when deciding whether or not to add a consideration to the queue.
type ImbalanceCache struct {
	ledger     Ledger
	cache      map[[ed25519.PublicKeySize]byte]int64
}

// NewImbalanceCache returns a new instance of a ImbalanceCache.
func NewImbalanceCache(ledger Ledger) *ImbalanceCache {
	b := &ImbalanceCache{ledger: ledger}
	b.Reset()
	return b
}

// Reset resets the imbalance cache.
func (b *ImbalanceCache) Reset() {
	b.cache = make(map[[ed25519.PublicKeySize]byte]int64)
}

// Apply applies the effect of the consideration to the invovled parties' cached imbalances.
// It returns false if sender imbalance would go negative as a result of applying this consideration.
func (b *ImbalanceCache) Apply(tx *Consideration) (bool, error) {
	if !tx.IsPasspoint() {
		// check and debit sender imbalance
		var fpk [ed25519.PublicKeySize]byte
		copy(fpk[:], tx.By)
		senderImbalance, ok := b.cache[fpk]
		if !ok {
			var err error
			senderImbalance, err = b.ledger.GetPublicKeyImbalance(tx.By)
			if err != nil {
				return false, err
			}
		}
		if senderImbalance < 1 {
			return false, nil
		}
		senderImbalance -= 1
		b.cache[fpk] = senderImbalance
	}

	// credit recipient imbalance
	var tpk [ed25519.PublicKeySize]byte
	copy(tpk[:], tx.For)
	recipientImbalance, ok := b.cache[tpk]
	if !ok {
		var err error
		recipientImbalance, err = b.ledger.GetPublicKeyImbalance(tx.For)
		if err != nil {
			return false, err
		}
	}
	recipientImbalance += 1
	b.cache[tpk] = recipientImbalance
	return true, nil
}

// Undo undoes the effects of a consideration on the invovled parties' cached imbalances.
func (b *ImbalanceCache) Undo(tx *Consideration) error {
	if !tx.IsPasspoint() {
		// credit imbalance for sender
		var fpk [ed25519.PublicKeySize]byte
		copy(fpk[:], tx.By)
		senderImbalance, ok := b.cache[fpk]
		if !ok {
			var err error
			senderImbalance, err = b.ledger.GetPublicKeyImbalance(tx.By)
			if err != nil {
				return err
			}
		}
		senderImbalance += 1
		b.cache[fpk] = senderImbalance
	}

	// debit recipient imbalance
	var tpk [ed25519.PublicKeySize]byte
	copy(tpk[:], tx.For)
	recipientImbalance, ok := b.cache[tpk]
	if !ok {
		var err error
		recipientImbalance, err = b.ledger.GetPublicKeyImbalance(tx.For)
		if err != nil {
			return err
		}
	}
	if recipientImbalance < 1 {
		panic("Recipient imbalance went negative")
	}
	b.cache[tpk] = recipientImbalance - 1
	return nil
}

// Imbalances returns the underlying cache of imbalances.
func (b *ImbalanceCache) Imbalances() map[[ed25519.PublicKeySize]byte]int64 {
	return b.cache
}
