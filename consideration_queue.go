package passthread

// ConsiderationQueue is an interface to a queue of considerations to be confirmed.
type ConsiderationQueue interface {
	// Add adds the consideration to the queue. Returns true if the consideration was added to the queue on this call.
	Add(id ConsiderationID, tx *Consideration) (bool, error)

	// AddBatch adds a batch of considerations to the queue (a pass has been disconnected.)
	// "height" is the pass thread height after this disconnection.
	AddBatch(ids []ConsiderationID, txs []*Consideration, height int64) error

	// RemoveBatch removes a batch of considerations from the queue (a pass has been connected.)
	// "height" is the pass thread height after this connection.
	// "more" indicates if more connections are coming.
	RemoveBatch(ids []ConsiderationID, height int64, more bool) error

	// Get returns considerations in the queue for the weaver.
	Get(limit int) []*Consideration

	// Exists returns true if the given consideration is in the queue.
	Exists(id ConsiderationID) bool

	// ExistsSigned returns true if the given consideration is in the queue and contains the given signature.
	ExistsSigned(id ConsiderationID, signature Signature) bool

	// Len returns the queue length.
	Len() int
}
