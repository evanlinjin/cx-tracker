package store

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"time"

	"go.etcd.io/bbolt"
)

var binaryEnc = binary.BigEndian

func encodeTime(t time.Time) []byte {
	b := make([]byte, 8)
	binaryEnc.PutUint64(b, uint64(t.Unix()))
	return b
}

func decodeTime(b []byte) time.Time {
	unix := int64(binaryEnc.Uint64(b))
	return time.Unix(unix, 0)
}

var (
	ErrBboltObjectNotExist      = errors.New("bbolt object does not exist")
	ErrBboltObjectAlreadyExists = errors.New("bbolt object already exists")
	ErrBboltInvalidValue        = errors.New("invalid value in bbolt db")
)

const (
	bboltFileMode        = os.FileMode(0600)
	bboltFileOpenTimeout = time.Second * 10
)

// OpenBboltDB opens a bbolt database file.
func OpenBboltDB(filename string) (*bbolt.DB, error) {
	opts := bbolt.DefaultOptions
	opts.Timeout = bboltFileOpenTimeout

	return bbolt.Open(filename, bboltFileMode, opts)
}

var (
	// specBucket is the identifier for the chain spec bucket
	//   key: [32B: genesis block hash]
	// value: [json encoded chain spec]
	specBucket = []byte("spec")

	// peersBucket is the identifier for the peers bucket
	//   key: [32B: genesis block hash]
	// value: [bucket of "addresses:timestamp"]
	peersBucket = []byte("client_nodes")

	// countBucket contains counts of various objects
	countBucket = []byte("count")
)

func objectCount(tx *bbolt.Tx, key []byte) uint64 {
	v := tx.Bucket(countBucket).Get(key)
	if len(v) != 8 {
		return 0
	}
	return binaryEnc.Uint64(v)
}

func incrementObjectCount(tx *bbolt.Tx, key []byte, delta uint64) error {
	b := tx.Bucket(countBucket)

	v := b.Get(key)
	if len(v) != 8 {
		v = make([]byte, 8)
	}
	binaryEnc.PutUint64(v, binaryEnc.Uint64(v)+delta)
	return b.Put(key, v)
}

func decrementObjectCount(tx *bbolt.Tx, key []byte, delta uint64) error {
	b := tx.Bucket(countBucket)

	v := b.Get(key)
	if len(v) != 8 {
		v = make([]byte, 8)
	}
	binaryEnc.PutUint64(v, binaryEnc.Uint64(v)-delta)
	return b.Put(key, v)
}

func doAsync(ctx context.Context, action func() error) error {
	errCh := make(chan error, 1)

	go func() {
		errCh <- action()
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}