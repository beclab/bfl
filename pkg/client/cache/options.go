package cache

import (
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
)

type Options struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Password string `json:"password" yaml:"password"`
	DB       int    `json:"db" yaml:"db"`
}

// NewRedisOptions returns options points to nowhere,
// because redis is not required for some components
func NewRedisOptions() *Options {
	return &Options{
		Host:     "",
		Port:     6379,
		Password: "",
		DB:       0,
	}
}

// Validate check options
func (r *Options) Validate() []error {
	errs := make([]error, 0)

	if r.Port == 0 {
		errs = append(errs, errors.New("invalid service port number"))
	}

	return errs
}

// AddFlags add option flags to command line flags,
// if redis-host left empty, the following options will be ignored.
func (r *Options) AddFlags(fs *pflag.FlagSet, s *Options) {
	fs.StringVar(&r.Host, "redis-host", s.Host, "Redis connection URL. If left blank, means redis is unnecessary, "+
		"redis will be disabled.")

	fs.IntVar(&r.Port, "redis-port", s.Port, "")
	fs.StringVar(&r.Password, "redis-password", s.Password, "")
	fs.IntVar(&r.DB, "redis-db", s.DB, "")
}
