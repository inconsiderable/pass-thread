package passthread

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"golang.org/x/crypto/ed25519"
)

// LedgerDisk is an on-disk implemenation of the Ledger interface using LevelDB.
type LedgerDisk struct {
	db         	*leveldb.DB
	passStore 	PassStorage
	conGraph 	*Graph
	prune      	bool // prune historic consideration and public key consideration indices
}

// NewLedgerDisk returns a new instance of LedgerDisk.
func NewLedgerDisk(dbPath string, readOnly, prune bool, passStore PassStorage, conGraph *Graph) (*LedgerDisk, error) {
	opts := opt.Options{ReadOnly: readOnly}
	db, err := leveldb.OpenFile(dbPath, &opts)
	if err != nil {
		return nil, err
	}
	return &LedgerDisk{db: db, passStore: passStore, conGraph: *&conGraph, prune: prune}, nil
}

// GetThreadTip returns the ID and the height of the pass at the current tip of the main thread.
func (l LedgerDisk) GetThreadTip() (*PassID, int64, error) {
	return getThreadTip(l.db)
}

// Sometimes we call this with *leveldb.DB or *leveldb.Snapshot
func getThreadTip(db leveldb.Reader) (*PassID, int64, error) {
	// compute db key
	key, err := computeThreadTipKey()
	if err != nil {
		return nil, 0, err
	}

	// fetch the id
	ctBytes, err := db.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}

	// decode the tip
	id, height, err := decodeThreadTip(ctBytes)
	if err != nil {
		return nil, 0, err
	}

	return id, height, nil
}

// GetPassIDForHeight returns the ID of the pass at the given pass thread height.
func (l LedgerDisk) GetPassIDForHeight(height int64) (*PassID, error) {
	return getPassIDForHeight(height, l.db)
}

// Sometimes we call this with *leveldb.DB or *leveldb.Snapshot
func getPassIDForHeight(height int64, db leveldb.Reader) (*PassID, error) {
	// compute db key
	key, err := computePassHeightIndexKey(height)
	if err != nil {
		return nil, err
	}

	// fetch the id
	idBytes, err := db.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// return it
	id := new(PassID)
	copy(id[:], idBytes)
	return id, nil
}

// SetBranchType sets the branch type for the given pass.
func (l LedgerDisk) SetBranchType(id PassID, branchType BranchType) error {
	// compute db key
	key, err := computeBranchTypeKey(id)
	if err != nil {
		return err
	}

	// write type
	wo := opt.WriteOptions{Sync: true}
	return l.db.Put(key, []byte{byte(branchType)}, &wo)
}

// GetBranchType returns the branch type for the given pass.
func (l LedgerDisk) GetBranchType(id PassID) (BranchType, error) {
	// compute db key
	key, err := computeBranchTypeKey(id)
	if err != nil {
		return UNKNOWN, err
	}

	// fetch type
	branchType, err := l.db.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return UNKNOWN, nil
	}
	if err != nil {
		return UNKNOWN, err
	}
	return BranchType(branchType[0]), nil
}

// ConnectPass connects a pass to the tip of the pass thread and applies the considerations to the ledger.
func (l LedgerDisk) ConnectPass(id PassID, pass *Pass) ([]ConsiderationID, error) {
	// sanity check
	tipID, _, err := l.GetThreadTip()
	if err != nil {
		return nil, err
	}
	if tipID != nil && *tipID != pass.Header.Previous {
		return nil, fmt.Errorf("Being asked to connect %s but previous %s does not match tip %s",
			id, pass.Header.Previous, *tipID)
	}

	// apply all resulting writes atomically
	batch := new(leveldb.Batch)

	imbalanceCache := NewImbalanceCache(l)
	txIDs := make([]ConsiderationID, len(pass.Considerations))

	for i, tx := range pass.Considerations {
		txID, err := tx.ID()
		if err != nil {
			return nil, err
		}
		txIDs[i] = txID

		// verify the consideration hasn't been processed already.
		// note that we can safely prune indices for considerations older than the previous series
		key, err := computeConsiderationIndexKey(txID)
		if err != nil {
			return nil, err
		}
		ok, err := l.db.Has(key, nil)
		if err != nil {
			return nil, err
		}
		if ok {
			return nil, fmt.Errorf("Consideration %s already processed", txID)
		}

		// set the consideration index now
		indexBytes, err := encodeConsiderationIndex(pass.Header.Height, i)
		if err != nil {
			return nil, err
		}
		batch.Put(key, indexBytes)

		txToApply := tx

		if tx.IsPasspoint() {
			// don't apply a passpoint to a imbalance until it's x passes deep.
			// during honest reorgs normal considerations usually get into the new most-work branch
			// but passpoints vanish. this mitigates the impact on UX when reorgs occur and considerations
			// depend on passpoints.
			txToApply = nil

			if pass.Header.Height-PASSPOINT_MATURITY >= 0 {
				// mature the passpoint from 100 passes ago now
				oldID, err := l.GetPassIDForHeight(pass.Header.Height - PASSPOINT_MATURITY)
				if err != nil {
					return nil, err
				}
				if oldID == nil {
					return nil, fmt.Errorf("Missing pass at height %d\n",
						pass.Header.Height-PASSPOINT_MATURITY)
				}

				// we could store the last 100 passpoints on our own in memory if we end up needing to
				oldTx, _, err := l.passStore.GetConsideration(*oldID, 0)
				if err != nil {
					return nil, err
				}
				if oldTx == nil {
					return nil, fmt.Errorf("Missing passpoint from pass %s\n", *oldID)
				}

				// apply it to the recipient's imbalance
				txToApply = oldTx
			}
		}

		if txToApply != nil {
			// check sender imbalance and update sender and receiver imbalances
			ok, err := imbalanceCache.Apply(txToApply)
			if err != nil {
				return nil, err
			}
			if !ok {
				txID, _ := txToApply.ID()
				return nil, fmt.Errorf("Sender has insufficient imbalance in consideration %s", txID)
			}

			if l.conGraph.IsParentDescendant(pubKeyToString(txToApply.For), pubKeyToString(txToApply.By)){
				txID, _ := txToApply.ID()
				return nil, fmt.Errorf("Sender is a descendant of recipient in consideration %s", txID)
			}
		}

		// associate this consideration with both parties
		if !tx.IsPasspoint() {
			key, err = computePubKeyConsiderationIndexKey(tx.By, &pass.Header.Height, &i)
			if err != nil {
				return nil, err
			}
			batch.Put(key, []byte{0x1})
		}
		key, err = computePubKeyConsiderationIndexKey(tx.For, &pass.Header.Height, &i)
		if err != nil {
			return nil, err
		}
		batch.Put(key, []byte{0x1})
	}

	// update recorded imbalances
	imbalances := imbalanceCache.Imbalances()
	for pubKeyBytes, imbalance := range imbalances {
		key, err := computePubKeyImbalanceKey(ed25519.PublicKey(pubKeyBytes[:]))
		if err != nil {
			return nil, err
		}
		if imbalance == 0 {
			batch.Delete(key)
		} else {
			imbalanceBytes, err := encodeNumber(imbalance)
			if err != nil {
				return nil, err
			}
			batch.Put(key, imbalanceBytes)
		}
	}

	// index the pass by height
	key, err := computePassHeightIndexKey(pass.Header.Height)
	if err != nil {
		return nil, err
	}
	batch.Put(key, id[:])

	// set this pass on the main thread
	key, err = computeBranchTypeKey(id)
	if err != nil {
		return nil, err
	}
	batch.Put(key, []byte{byte(MAIN)})

	// set this pass as the new tip
	key, err = computeThreadTipKey()
	if err != nil {
		return nil, err
	}
	ctBytes, err := encodeThreadTip(id, pass.Header.Height)
	if err != nil {
		return nil, err
	}
	batch.Put(key, ctBytes)

	// prune historic consideration and public key consideration indices now
	if l.prune && pass.Header.Height >= 2*PASSES_UNTIL_NEW_SERIES {
		if err := l.pruneIndices(pass.Header.Height-2*PASSES_UNTIL_NEW_SERIES, batch); err != nil {
			return nil, err
		}
	}

	// perform the writes
	wo := opt.WriteOptions{Sync: true}
	if err := l.db.Write(batch, &wo); err != nil {
		return nil, err
	}

	return txIDs, nil
}

// DisconnectPass disconnects a pass from the tip of the pass thread and undoes the effects of the considerations on the ledger.
func (l LedgerDisk) DisconnectPass(id PassID, pass *Pass) ([]ConsiderationID, error) {
	// sanity check
	tipID, _, err := l.GetThreadTip()
	if err != nil {
		return nil, err
	}
	if tipID == nil {
		return nil, fmt.Errorf("Being asked to disconnect %s but no tip is currently set",
			id)
	}
	if *tipID != id {
		return nil, fmt.Errorf("Being asked to disconnect %s but it does not match tip %s",
			id, *tipID)
	}

	// apply all resulting writes atomically
	batch := new(leveldb.Batch)

	imbalanceCache := NewImbalanceCache(l)
	txIDs := make([]ConsiderationID, len(pass.Considerations))

	// disconnect considerations in reverse order
	for i := len(pass.Considerations) - 1; i >= 0; i-- {
		tx := pass.Considerations[i]
		txID, err := tx.ID()
		if err != nil {
			return nil, err
		}
		// save the id
		txIDs[i] = txID

		// mark the consideration unprocessed now (delete its index)
		key, err := computeConsiderationIndexKey(txID)
		if err != nil {
			return nil, err
		}
		batch.Delete(key)

		txToUndo := tx
		if tx.IsPasspoint() {
			// passpoint doesn't affect recipient imbalance for x more passes
			txToUndo = nil

			if pass.Header.Height-PASSPOINT_MATURITY >= 0 {
				// undo the effect of the passpoint from x passes ago now
				oldID, err := l.GetPassIDForHeight(pass.Header.Height - PASSPOINT_MATURITY)
				if err != nil {
					return nil, err
				}
				if oldID == nil {
					return nil, fmt.Errorf("Missing pass at height %d\n",
						pass.Header.Height-PASSPOINT_MATURITY)
				}
				oldTx, _, err := l.passStore.GetConsideration(*oldID, 0)
				if err != nil {
					return nil, err
				}
				if oldTx == nil {
					return nil, fmt.Errorf("Missing passpoint from pass %s\n", *oldID)
				}

				// undo its effect on the recipient's imbalance
				txToUndo = oldTx
			}
		}

		if txToUndo != nil {
			// credit sender and debit recipient
			err = imbalanceCache.Undo(txToUndo)
			if err != nil {
				return nil, err
			}
		}

		// unassociate this consideration with both parties
		if !tx.IsPasspoint() {
			key, err = computePubKeyConsiderationIndexKey(tx.By, &pass.Header.Height, &i)
			if err != nil {
				return nil, err
			}
			batch.Delete(key)
		}
		key, err = computePubKeyConsiderationIndexKey(tx.For, &pass.Header.Height, &i)
		if err != nil {
			return nil, err
		}
		batch.Delete(key)
	}

	// update recorded imbalances
	imbalances := imbalanceCache.Imbalances()
	for pubKeyBytes, imbalance := range imbalances {
		key, err := computePubKeyImbalanceKey(ed25519.PublicKey(pubKeyBytes[:]))
		if err != nil {
			return nil, err
		}
		if imbalance == 0 {
			batch.Delete(key)
		} else {
			imbalanceBytes, err := encodeNumber(imbalance)
			if err != nil {
				return nil, err
			}
			batch.Put(key, imbalanceBytes)
		}
	}

	// remove this pass's index by height
	key, err := computePassHeightIndexKey(pass.Header.Height)
	if err != nil {
		return nil, err
	}
	batch.Delete(key)

	// set this pass on a side thread
	key, err = computeBranchTypeKey(id)
	if err != nil {
		return nil, err
	}
	batch.Put(key, []byte{byte(SIDE)})

	// set the previous pass as the thread tip
	key, err = computeThreadTipKey()
	if err != nil {
		return nil, err
	}
	ctBytes, err := encodeThreadTip(pass.Header.Previous, pass.Header.Height-1)
	if err != nil {
		return nil, err
	}
	batch.Put(key, ctBytes)

	// restore historic indices now
	if l.prune && pass.Header.Height >= 2*PASSES_UNTIL_NEW_SERIES {
		if err := l.restoreIndices(pass.Header.Height-2*PASSES_UNTIL_NEW_SERIES, batch); err != nil {
			return nil, err
		}
	}

	// perform the writes
	wo := opt.WriteOptions{Sync: true}
	if err := l.db.Write(batch, &wo); err != nil {
		return nil, err
	}

	return txIDs, nil
}

// Prune consideration and public key consideration indices created by the pass at the given height
func (l LedgerDisk) pruneIndices(height int64, batch *leveldb.Batch) error {
	// get the ID
	id, err := l.GetPassIDForHeight(height)
	if err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("Missing pass ID for height %d\n", height)
	}

	// fetch the pass
	pass, err := l.passStore.GetPass(*id)
	if err != nil {
		return err
	}
	if pass == nil {
		return fmt.Errorf("Missing pass %s\n", *id)
	}

	for i, tx := range pass.Considerations {
		txID, err := tx.ID()
		if err != nil {
			return err
		}

		// prune consideration index
		key, err := computeConsiderationIndexKey(txID)
		if err != nil {
			return err
		}
		batch.Delete(key)

		// prune public key consideration indices
		if !tx.IsPasspoint() {
			key, err = computePubKeyConsiderationIndexKey(tx.By, &pass.Header.Height, &i)
			if err != nil {
				return err
			}
			batch.Delete(key)
		}
		key, err = computePubKeyConsiderationIndexKey(tx.For, &pass.Header.Height, &i)
		if err != nil {
			return err
		}
		batch.Delete(key)
	}

	return nil
}

// Restore consideration and public key consideration indices created by the pass at the given height
func (l LedgerDisk) restoreIndices(height int64, batch *leveldb.Batch) error {
	// get the ID
	id, err := l.GetPassIDForHeight(height)
	if err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("Missing pass ID for height %d\n", height)
	}

	// fetch the pass
	pass, err := l.passStore.GetPass(*id)
	if err != nil {
		return err
	}
	if pass == nil {
		return fmt.Errorf("Missing pass %s\n", *id)
	}

	for i, tx := range pass.Considerations {
		txID, err := tx.ID()
		if err != nil {
			return err
		}

		// restore consideration index
		key, err := computeConsiderationIndexKey(txID)
		if err != nil {
			return err
		}
		indexBytes, err := encodeConsiderationIndex(pass.Header.Height, i)
		if err != nil {
			return err
		}
		batch.Put(key, indexBytes)

		// restore public key consideration indices
		if !tx.IsPasspoint() {
			key, err = computePubKeyConsiderationIndexKey(tx.By, &pass.Header.Height, &i)
			if err != nil {
				return err
			}
			batch.Put(key, []byte{0x1})
		}
		key, err = computePubKeyConsiderationIndexKey(tx.For, &pass.Header.Height, &i)
		if err != nil {
			return err
		}
		batch.Put(key, []byte{0x1})
	}

	return nil
}

// GetPublicKeyImbalance returns the current imbalance of a given public key.
func (l LedgerDisk) GetPublicKeyImbalance(pubKey ed25519.PublicKey) (int64, error) {
	// compute db key
	key, err := computePubKeyImbalanceKey(pubKey)
	if err != nil {
		return 0, err
	}

	// fetch imbalance
	imbalanceBytes, err := l.db.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	// decode and return it
	var imbalance int64
	buf := bytes.NewReader(imbalanceBytes)
	binary.Read(buf, binary.BigEndian, &imbalance)
	return imbalance, nil
}

// GetPublicKeyImbalances returns the current imbalance of the given public keys
// along with pass ID and height of the corresponding main thread tip.
func (l LedgerDisk) GetPublicKeyImbalances(pubKeys []ed25519.PublicKey) (
	map[[ed25519.PublicKeySize]byte]int64, *PassID, int64, error) {

	// get a consistent view across all queries
	snapshot, err := l.db.GetSnapshot()
	if err != nil {
		return nil, nil, 0, err
	}
	defer snapshot.Release()

	// get the thread tip
	tipID, tipHeight, err := getThreadTip(snapshot)
	if err != nil {
		return nil, nil, 0, err
	}

	imbalances := make(map[[ed25519.PublicKeySize]byte]int64)

	for _, pubKey := range pubKeys {
		// compute imbalance db key
		key, err := computePubKeyImbalanceKey(pubKey)
		if err != nil {
			return nil, nil, 0, err
		}

		var pk [ed25519.PublicKeySize]byte
		copy(pk[:], pubKey)

		// fetch imbalance
		imbalanceBytes, err := snapshot.Get(key, nil)
		if err == leveldb.ErrNotFound {
			imbalances[pk] = 0
			continue
		}
		if err != nil {
			return nil, nil, 0, err
		}

		// decode it
		var imbalance int64
		buf := bytes.NewReader(imbalanceBytes)
		binary.Read(buf, binary.BigEndian, &imbalance)

		// save it
		imbalances[pk] = imbalance
	}

	return imbalances, tipID, tipHeight, nil
}

// GetConsiderationIndex returns the index of a processed consideration.
func (l LedgerDisk) GetConsiderationIndex(id ConsiderationID) (*PassID, int, error) {
	// compute the db key
	key, err := computeConsiderationIndexKey(id)
	if err != nil {
		return nil, 0, err
	}

	// we want a consistent view during our two queries as height can change
	snapshot, err := l.db.GetSnapshot()
	if err != nil {
		return nil, 0, err
	}
	defer snapshot.Release()

	// fetch and decode the index
	indexBytes, err := snapshot.Get(key, nil)
	if err == leveldb.ErrNotFound {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	height, index, err := decodeConsiderationIndex(indexBytes)
	if err != nil {
		return nil, 0, err
	}

	// map height to pass id
	passID, err := getPassIDForHeight(height, snapshot)
	if err != nil {
		return nil, 0, err
	}

	// return it
	return passID, index, nil
}

// GetPublicKeyConsiderationIndicesRange returns consideration indices involving a given public key
// over a range of heights. If startHeight > endHeight this iterates in reverse.
func (l LedgerDisk) GetPublicKeyConsiderationIndicesRange(
	pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
	[]PassID, []int, int64, int, error) {

	if endHeight >= startHeight {
		// forward
		return l.getPublicKeyConsiderationIndicesRangeForward(
			pubKey, startHeight, endHeight, startIndex, limit)
	}

	// reverse
	return l.getPublicKeyConsiderationIndicesRangeReverse(
		pubKey, startHeight, endHeight, startIndex, limit)
}

// Iterate through consideration history going forward
func (l LedgerDisk) getPublicKeyConsiderationIndicesRangeForward(
	pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
	ids []PassID, indices []int, lastHeight int64, lastIndex int, err error) {
	startKey, err := computePubKeyConsiderationIndexKey(pubKey, &startHeight, &startIndex)
	if err != nil {
		return
	}

	endHeight += 1 // make it inclusive
	endKey, err := computePubKeyConsiderationIndexKey(pubKey, &endHeight, nil)
	if err != nil {
		return
	}

	heightMap := make(map[int64]*PassID)

	// we want a consistent view of this. heights can change out from under us otherwise
	snapshot, err := l.db.GetSnapshot()
	if err != nil {
		return
	}
	defer snapshot.Release()

	iter := snapshot.NewIterator(&util.Range{Start: startKey, Limit: endKey}, nil)
	for iter.Next() {
		_, lastHeight, lastIndex, err = decodePubKeyConsiderationIndexKey(iter.Key())
		if err != nil {
			iter.Release()
			return nil, nil, 0, 0, err
		}

		// lookup the pass id
		id, ok := heightMap[lastHeight]
		if !ok {
			var err error
			id, err = getPassIDForHeight(lastHeight, snapshot)
			if err != nil {
				iter.Release()
				return nil, nil, 0, 0, err
			}
			if id == nil {
				iter.Release()
				return nil, nil, 0, 0, fmt.Errorf(
					"No pass found at height %d", lastHeight)
			}
			heightMap[lastHeight] = id
		}

		ids = append(ids, *id)
		indices = append(indices, lastIndex)
		if limit != 0 && len(indices) == limit {
			break
		}
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return nil, nil, 0, 0, err
	}
	return
}

// Iterate through consideration history in reverse
func (l LedgerDisk) getPublicKeyConsiderationIndicesRangeReverse(
	pubKey ed25519.PublicKey, startHeight, endHeight int64, startIndex, limit int) (
	ids []PassID, indices []int, lastHeight int64, lastIndex int, err error) {
	endKey, err := computePubKeyConsiderationIndexKey(pubKey, &endHeight, nil)
	if err != nil {
		return
	}

	// make it inclusive
	startIndex += 1
	startKey, err := computePubKeyConsiderationIndexKey(pubKey, &startHeight, &startIndex)
	if err != nil {
		return
	}

	heightMap := make(map[int64]*PassID)

	// we want a consistent view of this. heights can change out from under us otherwise
	snapshot, err := l.db.GetSnapshot()
	if err != nil {
		return
	}
	defer snapshot.Release()

	iter := snapshot.NewIterator(&util.Range{Start: endKey, Limit: startKey}, nil)
	for ok := iter.Last(); ok; ok = iter.Prev() {
		_, lastHeight, lastIndex, err = decodePubKeyConsiderationIndexKey(iter.Key())
		if err != nil {
			iter.Release()
			return nil, nil, 0, 0, err
		}

		// lookup the pass id
		id, ok := heightMap[lastHeight]
		if !ok {
			var err error
			id, err = getPassIDForHeight(lastHeight, snapshot)
			if err != nil {
				iter.Release()
				return nil, nil, 0, 0, err
			}
			if id == nil {
				iter.Release()
				return nil, nil, 0, 0, fmt.Errorf(
					"No pass found at height %d", lastHeight)
			}
			heightMap[lastHeight] = id
		}

		ids = append(ids, *id)
		indices = append(indices, lastIndex)
		if limit != 0 && len(indices) == limit {
			break
		}
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return nil, nil, 0, 0, err
	}
	return
}

// Imbalance returns the total current ledger imbalance by summing the imbalance of all public keys.
// It's only used offline for verification purposes.
func (l LedgerDisk) Imbalance() (int64, error) {
	var total int64

	// compute the sum of all public key imbalances
	key, err := computePubKeyImbalanceKey(nil)
	if err != nil {
		return 0, err
	}
	iter := l.db.NewIterator(util.BytesPrefix(key), nil)
	for iter.Next() {
		var imbalance int64
		buf := bytes.NewReader(iter.Value())
		binary.Read(buf, binary.BigEndian, &imbalance)
		total += imbalance
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return 0, err
	}

	return total, nil
}

// GetPublicKeyImbalanceAt returns the public key imbalance at the given height.
// It's only used offline for historical and verification purposes.
// This is only accurate when the full pass thread is indexed (pruning disabled.)
func (l LedgerDisk) GetPublicKeyImbalanceAt(pubKey ed25519.PublicKey, height int64) (int64, error) {
	_, currentHeight, err := l.GetThreadTip()
	if err != nil {
		return 0, err
	}

	startKey, err := computePubKeyConsiderationIndexKey(pubKey, nil, nil)
	if err != nil {
		return 0, err
	}

	height += 1 // make it inclusive
	endKey, err := computePubKeyConsiderationIndexKey(pubKey, &height, nil)
	if err != nil {
		return 0, err
	}

	var imbalance int64
	iter := l.db.NewIterator(&util.Range{Start: startKey, Limit: endKey}, nil)
	for iter.Next() {
		_, height, index, err := decodePubKeyConsiderationIndexKey(iter.Key())
		if err != nil {
			iter.Release()
			return 0, err
		}

		if index == 0 && height > currentHeight-PASSPOINT_MATURITY {
			// passpoint isn't mature
			continue
		}

		id, err := l.GetPassIDForHeight(height)
		if err != nil {
			iter.Release()
			return 0, err
		}
		if id == nil {
			iter.Release()
			return 0, fmt.Errorf("No pass found at height %d", height)
		}

		tx, _, err := l.passStore.GetConsideration(*id, index)
		if err != nil {
			iter.Release()
			return 0, err
		}
		if tx == nil {
			iter.Release()
			return 0, fmt.Errorf("No consideration found in pass %s at index %d",
				*id, index)
		}

		if bytes.Equal(pubKey, tx.For) {
			imbalance += 1
		} else if bytes.Equal(pubKey, tx.By) {
			imbalance -= 1
		} else {
			iter.Release()
			txID, _ := tx.ID()
			return 0, fmt.Errorf("Consideration %s doesn't involve the public key", txID)
		}
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return 0, err
	}
	return imbalance, nil
}

// Close is called to close any underlying storage.
func (l LedgerDisk) Close() error {
	return l.db.Close()
}

// leveldb schema

// T                    -> {bid}{height} (main thread tip)
// B{bid}               -> main|side|orphan (1 byte)
// h{height}            -> {bid}
// t{txid}              -> {height}{index} (prunable up to the previous series)
// k{pk}{height}{index} -> 1 (not strictly necessary. probably should make it optional by flag)
// b{pk}                -> {imbalance} (we always need all of this table)

const threadTipPrefix = 'T'

const branchTypePrefix = 'B'

const passHeightIndexPrefix = 'h'

const considerationIndexPrefix = 't'

const pubKeyConsiderationIndexPrefix = 'k'

const pubKeyImbalancePrefix = 'b'

func computeBranchTypeKey(id PassID) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(branchTypePrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, id[:]); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func computePassHeightIndexKey(height int64) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(passHeightIndexPrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, height); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func computeThreadTipKey() ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(threadTipPrefix); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func computeConsiderationIndexKey(id ConsiderationID) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(considerationIndexPrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, id[:]); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func computePubKeyConsiderationIndexKey(
	pubKey ed25519.PublicKey, height *int64, index *int) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(pubKeyConsiderationIndexPrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, pubKey); err != nil {
		return nil, err
	}
	if height == nil {
		return key.Bytes(), nil
	}
	if err := binary.Write(key, binary.BigEndian, *height); err != nil {
		return nil, err
	}
	if index == nil {
		return key.Bytes(), nil
	}
	index32 := int32(*index)
	if err := binary.Write(key, binary.BigEndian, index32); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func decodePubKeyConsiderationIndexKey(key []byte) (ed25519.PublicKey, int64, int, error) {
	buf := bytes.NewBuffer(key)
	if _, err := buf.ReadByte(); err != nil {
		return nil, 0, 0, err
	}
	var pubKey [ed25519.PublicKeySize]byte
	if err := binary.Read(buf, binary.BigEndian, pubKey[:32]); err != nil {
		return nil, 0, 0, err
	}
	var height int64
	if err := binary.Read(buf, binary.BigEndian, &height); err != nil {
		return nil, 0, 0, err
	}
	var index int32
	if err := binary.Read(buf, binary.BigEndian, &index); err != nil {
		return nil, 0, 0, err
	}
	return ed25519.PublicKey(pubKey[:]), height, int(index), nil
}

func computePubKeyImbalanceKey(pubKey ed25519.PublicKey) ([]byte, error) {
	key := new(bytes.Buffer)
	if err := key.WriteByte(pubKeyImbalancePrefix); err != nil {
		return nil, err
	}
	if err := binary.Write(key, binary.BigEndian, pubKey); err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func encodeThreadTip(id PassID, height int64) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, id); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, height); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeThreadTip(ctBytes []byte) (*PassID, int64, error) {
	buf := bytes.NewBuffer(ctBytes)
	id := new(PassID)
	if err := binary.Read(buf, binary.BigEndian, id); err != nil {
		return nil, 0, err
	}
	var height int64
	if err := binary.Read(buf, binary.BigEndian, &height); err != nil {
		return nil, 0, err
	}
	return id, height, nil
}

func encodeNumber(num int64) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, num); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeConsiderationIndex(height int64, index int) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, height); err != nil {
		return nil, err
	}
	index32 := int32(index)
	if err := binary.Write(buf, binary.BigEndian, index32); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeConsiderationIndex(indexBytes []byte) (int64, int, error) {
	buf := bytes.NewBuffer(indexBytes)
	var height int64
	if err := binary.Read(buf, binary.BigEndian, &height); err != nil {
		return 0, 0, err
	}
	var index int32
	if err := binary.Read(buf, binary.BigEndian, &index); err != nil {
		return 0, 0, err
	}
	return height, int(index), nil
}