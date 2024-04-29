package cache

import (
	"fmt"
	"time"

	"github.com/go-redis/redis"
	"github.com/pkg/errors"
)

type Client struct {
	client *redis.Client
}

// NewRedisClient new a redis client
func NewRedisClient(o *Options) (Interface, error) {
	var r Client

	redisOptions := &redis.Options{
		Addr:               fmt.Sprintf("%s:%d", o.Host, o.Port),
		Password:           o.Password,
		DB:                 o.DB,
		PoolSize:           2,
		MinIdleConns:       1,
		IdleCheckFrequency: 30 * time.Second,
	}

	r.client = redis.NewClient(redisOptions)

	if err := r.client.Ping().Err(); err != nil {
		r.client.Close()
		return nil, errors.Errorf("ping redis err, %v", err)
	}

	return &r, nil
}

func (r *Client) Close() error {
	if err := r.client.Close(); err != nil {
		return errors.Errorf("close redis err: %v", err)
	}
	return nil
}

func (r *Client) Get(key string) (string, error) {
	return r.client.Get(key).Result()
}

func (r *Client) Keys(pattern string) ([]string, error) {
	return r.client.Keys(pattern).Result()
}

func (r *Client) Set(key string, value string, duration time.Duration) error {
	return r.client.Set(key, value, duration).Err()
}

func (r *Client) Del(keys ...string) error {
	return r.client.Del(keys...).Err()
}

func (r *Client) Exists(keys ...string) (bool, error) {
	existedKeys, err := r.client.Exists(keys...).Result()
	if err != nil {
		return false, err
	}

	return len(keys) == int(existedKeys), nil
}

func (r *Client) Expire(key string, duration time.Duration) error {
	return r.client.Expire(key, duration).Err()
}
