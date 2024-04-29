package store

import (
	"bytetrade.io/web3os/bfl/pkg/constants"
	"github.com/cockroachdb/pebble"
	"k8s.io/klog/v2"
)

const (
	UserDataStorePrefix = "userdata"
)

type pebbleStore struct {
	Store
	db   *pebble.DB
	name string
}

func NewPebbleStore() (Store, error) {

	store := &pebbleStore{}
	return store, nil
}

func (ps *pebbleStore) Open(username string) error {
	if ps.db != nil {
		if ps.name == username {
			// user db is being opened
			return nil
		}

		// Open a single user db at a time, close first
		ps.Close()
		ps.db = nil
	}

	// open db with user context
	db, err := pebble.Open(constants.UserAppDataPath+"/"+UserDataStorePrefix+"."+username, &pebble.Options{})
	if err != nil {
		return err
	}

	ps.db = db
	ps.name = username

	return nil
}

func (ps *pebbleStore) Get(key []byte) ([]byte, error) {
	if ps.db == nil {
		return nil, ErrStoreNotOpened
	}

	if len(key) > 0 {
		value, closer, err := ps.db.Get(key)
		if err != nil {
			if err == pebble.ErrNotFound {
				return nil, ErrKeyNotFound
			}
			return nil, err
		}

		if err := closer.Close(); err != nil {
			klog.Error(err)
			// TODO: return error
		}

		return value, nil
	}
	return nil, nil
}

// get data with a key prefix
func (ps *pebbleStore) MGet(keyPrefix []byte) ([]Entry, error) {
	if ps.db == nil {
		return nil, ErrStoreNotOpened
	}

	if len(keyPrefix) > 0 {

		// convert prefix => prefiy
		keyUpperBound := func(b []byte) []byte {
			end := make([]byte, len(b))
			copy(end, b)
			for i := len(end) - 1; i >= 0; i-- {
				end[i] = end[i] + 1
				if end[i] != 0 {
					return end[:i+1]
				}
			}
			return nil // no upper-bound
		}

		prefixIterOptions := func(prefix []byte) *pebble.IterOptions {
			return &pebble.IterOptions{
				LowerBound: prefix,
				UpperBound: keyUpperBound(prefix),
			}
		}

		iter := ps.db.NewIter(prefixIterOptions(keyPrefix))
		result := new([]Entry)
		for iter.First(); iter.Valid(); iter.Next() {
			*result = append(*result, Entry{Key: string(iter.Key()), Value: iter.Value()})
		}

		if err := iter.Close(); err != nil {
			klog.Error(err)
		}

		return *result, nil
	}

	return nil, nil
}

func (ps *pebbleStore) Set(key []byte, value []byte) error {
	if ps.db == nil {
		return ErrStoreNotOpened
	}

	if len(key) > 0 && len(value) > 0 {
		return ps.db.Set(key, value, pebble.Sync)
	}

	return nil
}

func (ps *pebbleStore) Delete(key []byte) error {
	if ps.db == nil {
		return ErrStoreNotOpened
	}

	if len(key) > 0 {
		return ps.db.Delete(key, pebble.Sync)
	}
	return nil
}

func (ps *pebbleStore) Close() {
	if ps.db == nil {
		return
	}

	if err := ps.db.Close(); err != nil {
		klog.Fatal(err)
	}
}
