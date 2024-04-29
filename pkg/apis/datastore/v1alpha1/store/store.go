package store

import (
	"encoding/json"
	"errors"
)

type Entry struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

var (
	ErrKeyNotFound    = errors.New("key not found")
	ErrStoreNotOpened = errors.New("store not opened")
)

type Store interface {
	Get(key []byte) ([]byte, error)
	MGet(keyPrefix []byte) ([]Entry, error)
	Set(key []byte, value []byte) error
	Delete(key []byte) error

	// Create(name string) error
	// Drop(name string) error

	Open(name string) error
	Close()
}
