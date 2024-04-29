package cache

import (
	"sync"

	"github.com/pkg/errors"
)

var syncOnce = new(sync.Once)

var RedisClient Interface

func Init(o *Options) error {
	if o == nil {
		return errors.New("redis option is nil")
	}

	client, err := NewRedisClient(o)
	if err != nil {
		return err
	}

	syncOnce.Do(func() {
		RedisClient = client
	})
	return nil
}
