package nginx

import (
	"os"
	"os/exec"

	"github.com/mitchellh/go-ps"
)

const (
	DefNgxBinary               = "/sbin/nginx"
	DefNgxCfgPath              = "/etc/nginx/nginx.conf"
	DefNgxSSLCertificationPath = "/etc/nginx/ssl"
)

// NginxCommand stores context around a given nginx executable path
type NginxCommand struct {
	binary   string
	confPath string
}

// NewNginxCommand returns a new NginxCommand from which path
// has been detected from environment variable NGINX_BINARY or default
func NewNginxCommand() *NginxCommand {
	command := NginxCommand{
		binary:   DefNgxBinary,
		confPath: DefNgxCfgPath,
	}
	binary := os.Getenv("NGINX_BINARY")
	if binary != "" {
		command.binary = binary
	}

	ngxCfgPath := os.Getenv("NGINX_CONF_PATH")
	if ngxCfgPath != "" {
		command.confPath = ngxCfgPath
	}
	return &command
}

func (n *NginxCommand) StartCmd(args ...string) *exec.Cmd {
	var cmdArgs []string

	cmdArgs = append(cmdArgs, "-c", n.confPath)
	cmdArgs = append(cmdArgs, args...)
	return exec.Command(n.binary, cmdArgs...)
}

func (n *NginxCommand) output(args ...string) ([]byte, error) {
	return exec.Command(n.binary, args...).CombinedOutput()
}

// Test checks if config file is a syntax valid nginx configuration
func (n *NginxCommand) Test(cfg string) ([]byte, error) {
	var confPath = n.confPath
	if cfg != "" {
		confPath = cfg
	}
	return n.output("-c", confPath, "-t")
}

func (n *NginxCommand) Reload() ([]byte, error) {
	return n.output("-s", "reload")
}

func (n *NginxCommand) Quit() ([]byte, error) {
	return n.output("-s", "quit")
}

func (n *NginxCommand) Version() ([]byte, error) {
	return n.output("-v")
}

func (n *NginxCommand) VersionAndOption() ([]byte, error) {
	return n.output("-V")
}

func IsRunning() bool {
	processes, _ := ps.Processes()
	for _, p := range processes {
		if p.Executable() == "nginx" {
			return true
		}
	}

	return false
}
