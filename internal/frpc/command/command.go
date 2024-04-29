package command

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"os/exec"
	"time"

	"bytetrade.io/web3os/bfl/internal/frpc"
	"bytetrade.io/web3os/bfl/pkg/apis/iam/v1alpha1/operator"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils/file"
	"bytetrade.io/web3os/bfl/pkg/utils/k8sutil"
	"github.com/mitchellh/go-ps"
	"github.com/pkg/errors"
)

const (
	DefaultFrpcBinary  = "/frpc"
	DefaultFrpcCfgPath = "/etc/frp/frpc.ini"

	FrpConfigTmpl = `
{{ $l4ProxySSLPort := .L4ProxySSLPort }}	
{{ $masterIp := .MasterIp }}	

serverAddr = "{{ .FrpServer }}"
serverPort = 7000
webServer.port = 7400
auth.method = "jws"
auth.jws = "{{ .JWSToken }}"
user = "{{ .TerminusName }}"
loginFailExit = false


[[proxies]]
name = "web"
type = "http"
localPort = 80
localIp = "{{ .MasterIp }}"
customDomains = ["{{ .UserZone }}"]
transport.proxyProtocolVersion = "v1"

[[proxies]]
name = "web_wildcard"
type = "http"
localPort = 80
localIp = "{{ .MasterIp }}"
customDomains = ["*.{{- .UserZone }}"]
transport.proxyProtocolVersion = "v1"

[[proxies]]
name = "web_ssl"
type = "https"
localPort = {{ .L4ProxySSLPort }}
localIp = "{{ .MasterIp }}"
customDomains = ["{{ .UserZone }}"]
transport.proxyProtocolVersion = "v1"

[[proxies]]
name = "web_ssl_wildcard"
type = "https"
localPort = {{ .L4ProxySSLPort }}
localIp = "{{ .MasterIp }}"
customDomains = ["*.{{- .UserZone }}"]
transport.proxyProtocolVersion = "v1"

{{- if gt (len .CustomDomains) 0 -}}
{{ range $server := .CustomDomains }}
{{ if ne $server "" }}
[[proxies]]
name = "web_ssl_{{ $server }}"
type = "https"
localPort = {{ $l4ProxySSLPort }}
localIp = "{{ $masterIp }}"
customDomains = ["{{ $server }}"]
transport.proxyProtocolVersion = "v1"
{{- end -}}
{{- end -}}
{{ end }}

`
)

type FrpcCommand struct {
	binary          string
	confPath        string
	customDomains   []string
	frpcConfig      *frpc.FrpcConfig
	templateContent string
}

func NewFrpcCommand() *FrpcCommand {
	return &FrpcCommand{
		binary:   DefaultFrpcBinary,
		confPath: DefaultFrpcCfgPath,
	}
}

func (f *FrpcCommand) StartCmd(args ...string) *exec.Cmd {
	var cmdArgs []string

	cmdArgs = append(cmdArgs, "-c", f.confPath)
	cmdArgs = append(cmdArgs, args...)
	return exec.Command(f.binary, cmdArgs...)
}

func (f *FrpcCommand) GetFrpcConfig() error {
	var userOp, err = operator.NewUserOperator()
	if err != nil {
		return errors.Errorf("new user operator err, %v", err)
	}

	user, err := userOp.GetUser(constants.Username)
	if err != nil {
		return errors.Errorf("get user err, %v", err)
	}

	ip, err := k8sutil.GetL4ProxyNodeIP(context.Background(), 10*time.Second)
	if err != nil {
		return errors.Errorf("no master hostIP: %v", err)
	}

	f.frpcConfig = &frpc.FrpcConfig{
		LocalDomainIp: *ip,
		FrpServer:     constants.FrpServer,
		TerminusName:  constants.TerminusName(userOp.GetUserAnnotation(user, constants.UserAnnotationTerminusNameKey)),
		JWSToken:      userOp.GetUserAnnotation(user, constants.UserCertManagerJWSToken),
	}

	return nil
}

func (f *FrpcCommand) output(args ...string) ([]byte, error) {
	return exec.Command(f.binary, args...).CombinedOutput()
}

func (f *FrpcCommand) Reload() ([]byte, error) {
	return f.output("reload")
}

func (f *FrpcCommand) Test(cfg string) ([]byte, error) {
	var confPath = f.confPath
	if cfg != "" {
		confPath = cfg
	}
	return f.output("-c", confPath, "verify")
}

func (f *FrpcCommand) UpdateCustomDomains(customDomains []string) error {
	f.customDomains = customDomains
	return f.GenerateConfig()
}

func (f *FrpcCommand) GenerateConfig() error {
	data := struct {
		FrpServer      string
		TerminusName   string
		UserZone       string
		MasterIp       string
		JWSToken       string
		L4ProxySSLPort int
		CustomDomains  []string
	}{
		FrpServer:      f.frpcConfig.FrpServer,
		TerminusName:   string(f.frpcConfig.TerminusName),
		UserZone:       f.frpcConfig.TerminusName.UserZone(),
		MasterIp:       f.frpcConfig.LocalDomainIp,
		JWSToken:       f.frpcConfig.JWSToken,
		L4ProxySSLPort: constants.L4ProxySSLPort,
		CustomDomains:  f.customDomains,
	}

	t, err := template.New("frpc").Parse(FrpConfigTmpl)
	if err != nil {
		return err
	}

	var bf bytes.Buffer
	if err = t.Execute(&bf, data); err != nil {
		return fmt.Errorf("execute template err, %v", err)
	}

	f.templateContent = bf.String()
	return file.WriteFile(f.confPath, f.templateContent, true)
}

func (f *FrpcCommand) GetTemplate() string {
	return f.templateContent
}

func IsRunning() bool {
	processes, _ := ps.Processes()
	for _, p := range processes {
		if p.Executable() == "frpc" {
			return true
		}
	}

	return false
}
