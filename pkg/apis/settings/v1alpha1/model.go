package v1alpha1

import (
	"bytes"
	"fmt"
	"text/template"

	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	applyAppsv1 "k8s.io/client-go/applyconfigurations/apps/v1"
	applyCorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	applyMetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/utils/pointer"
)

var (
	FrpDeploymentReplicas int32 = 1

	FrpDeploymentName = "frp-agent"

	L4ProxyDeploymentName = "l4-bfl-proxy"

	L4ProxyDeploymentReplicas int32 = 1

	CloudflaredDeploymentName = "cloudflare-tunnel"

	CloudflareDeploymentReplicas int32 = 1

	FrpConfigTmpl = `
{{ $l4ProxySSLPort := .L4ProxySSLPort }}	

[common]
server_addr = {{ .FrpServer }}
server_port = 7000
admin_port = 7400
authentication_methd = token
token = bytetrade.com@did
user = {{ .User }}

[web]
type = http
local_port = 80
local_ip = __MASTER_IP__
custom_domains = {{ .UserZone }}

[web_wildcard]
type = http
local_port = 80
local_ip = __MASTER_IP__
custom_domains = *.{{- .UserZone }}

[web_ssl]
type = https
local_port = {{ .L4ProxySSLPort }}
local_ip = __MASTER_IP__
custom_domains = {{ .UserZone }}
proxy_protocol_version = v1

{{- if gt (len .CustomDomains) 0 -}}
{{ range $server := .CustomDomains }}
{{ if ne $server "" }}
[web_ssl_{{ $server }}]
type = https
local_port = {{ $l4ProxySSLPort }}
local_ip = __MASTER_IP__
custom_domains = {{ $server }}
proxy_protocol_version = v1
{{- end -}}
{{- end -}}
{{ end }}

[web_ssl_wildcard]
type = https
local_port = {{ .L4ProxySSLPort }}
local_ip = __MASTER_IP__
custom_domains = *.{{- .UserZone }}
proxy_protocol_version = v1
`
)

const (
	ServiceEnabled  = "enabled"
	ServiceDisabled = "disabled"
)

type AccessLevel uint64

const (
	_ AccessLevel = iota

	WorldWide
	Public
	Protected
	Private
)

type AuthPolicy string

const (
	OneFactor = "one_factor"
	TwoFactor = "two_factor"
)

const DefaultAuthPolicy = TwoFactor

const DefaultPodsCIDR = "10.233.64.0/18"

type PostTerminusName struct {
	JWSSignature string `json:"jws_signature"`
	DID          string `json:"did"`
}

type PostEnableSSL struct {
	FrpServer    string `json:"frp_server"`
	IP           string `json:"ip"`
	EnableTunnel bool   `json:"enable_tunnel"`
}

type ServiceStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	URL    string `json:"url"`
}

type ResponseServices struct {
	Services []ServiceStatus `json:"services"`
}

type LauncherAccessPolicy struct {
	AccessLevel AccessLevel `json:"access_level"`
	AuthPolicy  AuthPolicy  `json:"auth_policy"`
	AllowCIDRs  []string    `json:"allow_cidrs,omitempty"`
}

type PublicDomainAccessPolicy struct {
	DenyAll int `json:"deny_all"`
	// AllowedDomains []string `json:"allowed_domains"`
}

type PostLocale struct {
	Language string `json:"language"`
	Location string `json:"location"`
}

type TunnelRequest struct {
	Name    string `json:"name"`
	Service string `json:"service"`
}

type TunnelResponseData struct {
	Token string `json:"token"`
}

type TunnelResponse struct {
	Success bool                `json:"success"`
	Data    *TunnelResponseData `json:"data"`
}

func parseFrpConfig(terminusName constants.TerminusName, frpServer string) (string, string, error) {
	data := struct {
		FrpServer      string
		User           string
		UserZone       string
		L4ProxySSLPort int
		CustomDomains  []string
	}{
		FrpServer:      frpServer,
		User:           terminusName.UserName(),
		UserZone:       terminusName.UserZone(),
		L4ProxySSLPort: constants.L4ProxySSLPort,
		CustomDomains:  nil,
	}
	t, err := template.New("frpc").Parse(FrpConfigTmpl)
	if err != nil {
		return "", "", fmt.Errorf("parse frpc template err, %v", err)
	}

	var bf bytes.Buffer
	if err = t.Execute(&bf, data); err != nil {
		return "", "", fmt.Errorf("execute template err, %v", err)
	}
	return terminusName.UserAndDomain()[1], bf.String(), nil
}

func NewL4ProxyDeploymentApplyConfiguration(namespace, serviceAccountName string, port int) applyAppsv1.DeploymentApplyConfiguration {
	imagePullPolicy := corev1.PullAlways
	strategyRecreate := appsv1.RecreateDeploymentStrategyType
	dnsPolicy := corev1.DNSClusterFirstWithHostNet
	protocolTCP := corev1.ProtocolTCP
	containerPort := intstr.FromInt(port)
	nodeSelectorOperatorIn := corev1.NodeSelectorOpIn
	nodeSelectorOperatorExists := corev1.NodeSelectorOpExists

	imageVersion := utils.EnvOrDefault("L4_PROXY_IMAGE_VERSION", "v0.2.0")
	imageName := fmt.Sprintf("%s:%s", utils.EnvOrDefault("L4_PROXY_IMAGE_NAME", constants.L4ProxyImage), imageVersion)

	return applyAppsv1.DeploymentApplyConfiguration{
		TypeMetaApplyConfiguration: applyMetav1.TypeMetaApplyConfiguration{
			Kind:       pointer.String("Deployment"),
			APIVersion: pointer.String(appsv1.SchemeGroupVersion.String()),
		},
		ObjectMetaApplyConfiguration: &applyMetav1.ObjectMetaApplyConfiguration{
			Name:      pointer.String(L4ProxyDeploymentName),
			Namespace: pointer.String(namespace),
			Labels: map[string]string{
				"app": L4ProxyDeploymentName,
			},
			Annotations: nil,
		},
		Spec: &applyAppsv1.DeploymentSpecApplyConfiguration{
			Replicas: pointer.Int32(L4ProxyDeploymentReplicas),
			Strategy: &applyAppsv1.DeploymentStrategyApplyConfiguration{
				Type: &strategyRecreate,
			},
			Selector: &applyMetav1.LabelSelectorApplyConfiguration{
				MatchLabels: map[string]string{
					"app": L4ProxyDeploymentName,
				},
			},
			Template: &applyCorev1.PodTemplateSpecApplyConfiguration{
				ObjectMetaApplyConfiguration: &applyMetav1.ObjectMetaApplyConfiguration{
					Labels: map[string]string{
						"app": L4ProxyDeploymentName,
					},
				},
				Spec: &applyCorev1.PodSpecApplyConfiguration{
					HostNetwork:        pointer.Bool(true),
					DNSPolicy:          &dnsPolicy,
					ServiceAccountName: pointer.String(serviceAccountName),
					Affinity: &applyCorev1.AffinityApplyConfiguration{
						NodeAffinity: &applyCorev1.NodeAffinityApplyConfiguration{
							PreferredDuringSchedulingIgnoredDuringExecution: []applyCorev1.PreferredSchedulingTermApplyConfiguration{
								{
									Weight: pointer.Int32(10),
									Preference: &applyCorev1.NodeSelectorTermApplyConfiguration{
										MatchExpressions: []applyCorev1.NodeSelectorRequirementApplyConfiguration{
											{
												Key:      pointer.String("kubernetes.io/os"),
												Operator: &nodeSelectorOperatorIn,
												Values:   []string{"linux"},
											},
											{
												Key:      pointer.String("node-role.kubernetes.io/master"),
												Operator: &nodeSelectorOperatorExists,
											},
										},
									},
								},
							},
						},
					},
					Containers: []applyCorev1.ContainerApplyConfiguration{
						{
							Name:            pointer.String("proxy"),
							Image:           pointer.String(imageName),
							ImagePullPolicy: &imagePullPolicy,
							Command: []string{
								"/l4-bfl-proxy",
								"-w",
								"4",
							},
							Env: []applyCorev1.EnvVarApplyConfiguration{
								{
									Name: pointer.String("NODE_IP"),
									ValueFrom: &applyCorev1.EnvVarSourceApplyConfiguration{
										FieldRef: &applyCorev1.ObjectFieldSelectorApplyConfiguration{
											FieldPath: pointer.String("status.hostIP"),
										},
									},
								},
							},
							LivenessProbe: &applyCorev1.ProbeApplyConfiguration{
								HandlerApplyConfiguration: applyCorev1.HandlerApplyConfiguration{
									TCPSocket: &applyCorev1.TCPSocketActionApplyConfiguration{
										Port: &containerPort,
									},
								},
								FailureThreshold:    pointer.Int32(8),
								InitialDelaySeconds: pointer.Int32(3),
								PeriodSeconds:       pointer.Int32(5),
								TimeoutSeconds:      pointer.Int32(10),
							},
							ReadinessProbe: &applyCorev1.ProbeApplyConfiguration{
								HandlerApplyConfiguration: applyCorev1.HandlerApplyConfiguration{
									TCPSocket: &applyCorev1.TCPSocketActionApplyConfiguration{
										Port: &containerPort,
									},
								},
								FailureThreshold: pointer.Int32(5),
								PeriodSeconds:    pointer.Int32(3),
								TimeoutSeconds:   pointer.Int32(10),
							},
							Ports: []applyCorev1.ContainerPortApplyConfiguration{
								{
									ContainerPort: pointer.Int32(int32(port)),
									Protocol:      &protocolTCP,
								},
							},
						},
					},
				},
			},
		},
	}
}

func NewFrpDeploymentApplyConfiguration(frpConfig string, frpServer string) applyAppsv1.DeploymentApplyConfiguration {
	volumeName := "frp-config"
	imagePullPolicy := corev1.PullIfNotPresent

	imageVersion := utils.EnvOrDefault("FRPC_IMAGE_VERSION", "v1.0.0")
	imageName := fmt.Sprintf("%s:%s", utils.EnvOrDefault("FRPC_IMAGE_NAME", constants.FrpcImage), imageVersion)

	return applyAppsv1.DeploymentApplyConfiguration{
		TypeMetaApplyConfiguration: applyMetav1.TypeMetaApplyConfiguration{
			Kind:       pointer.String("Deployment"),
			APIVersion: pointer.String(appsv1.SchemeGroupVersion.String()),
		},
		ObjectMetaApplyConfiguration: &applyMetav1.ObjectMetaApplyConfiguration{
			Name:      pointer.String(FrpDeploymentName),
			Namespace: pointer.String(constants.Namespace),
			Labels: map[string]string{
				"app":                                  FrpDeploymentName,
				"applications.app.bytetrade.io/author": constants.AnnotationGroup,
				"applications.app.bytetrade.io/owner":  constants.Username,
			},
			Annotations: map[string]string{
				"frp-server": frpServer,
			},
		},
		Spec: &applyAppsv1.DeploymentSpecApplyConfiguration{
			Replicas: pointer.Int32(FrpDeploymentReplicas),

			Selector: &applyMetav1.LabelSelectorApplyConfiguration{
				MatchLabels: map[string]string{
					"app": FrpDeploymentName,
				},
			},
			Template: &applyCorev1.PodTemplateSpecApplyConfiguration{
				ObjectMetaApplyConfiguration: &applyMetav1.ObjectMetaApplyConfiguration{
					Labels: map[string]string{
						"app": FrpDeploymentName,
					},
				},
				Spec: &applyCorev1.PodSpecApplyConfiguration{
					SchedulerName:      pointer.String("default-scheduler"),
					ServiceAccountName: pointer.String("bytetrade-controller"),
					Volumes: []applyCorev1.VolumeApplyConfiguration{
						{
							Name: pointer.String(volumeName),
							VolumeSourceApplyConfiguration: applyCorev1.VolumeSourceApplyConfiguration{
								EmptyDir: &applyCorev1.EmptyDirVolumeSourceApplyConfiguration{},
							},
						},
					},
					Containers: []applyCorev1.ContainerApplyConfiguration{
						{
							Name:            pointer.String("agent"),
							Image:           pointer.String(imageName),
							ImagePullPolicy: &imagePullPolicy,
							Command: []string{
								"/frpc-agent", "-user", constants.Username, "-frp-server", frpServer,
							},
							// When restarting the server, frpc will experience a timeout when connecting to the server. Here, we have added a startup check.
							StartupProbe: &applyCorev1.ProbeApplyConfiguration{
								HandlerApplyConfiguration: applyCorev1.HandlerApplyConfiguration{
									Exec: &applyCorev1.ExecActionApplyConfiguration{Command: []string{
										"/frpc", "status", "-c", "/etc/frp/frpc.ini",
									}}},
								FailureThreshold:    pointer.Int32(8),
								InitialDelaySeconds: pointer.Int32(5),
								PeriodSeconds:       pointer.Int32(5),
								TimeoutSeconds:      pointer.Int32(10),
							},
							LivenessProbe: &applyCorev1.ProbeApplyConfiguration{
								HandlerApplyConfiguration: applyCorev1.HandlerApplyConfiguration{
									Exec: &applyCorev1.ExecActionApplyConfiguration{
										Command: []string{
											"/bin/sh", "-c", "/usr/bin/pgrep -x /frpc-agent",
										},
									},
								},
								FailureThreshold:    pointer.Int32(8),
								InitialDelaySeconds: pointer.Int32(3),
								PeriodSeconds:       pointer.Int32(5),
								TimeoutSeconds:      pointer.Int32(10),
							},
							VolumeMounts: []applyCorev1.VolumeMountApplyConfiguration{
								{
									Name:      pointer.String(volumeName),
									MountPath: pointer.String("/etc/frp"),
									ReadOnly:  pointer.Bool(false),
								},
							},
						},
					},
				},
			},
		},
	}
}

func NewCloudflareDeploymentApplyConfiguration(token string) applyAppsv1.DeploymentApplyConfiguration {
	imagePullPolicy := corev1.PullIfNotPresent

	imageVersion := utils.EnvOrDefault("CLOUDFLARED_IMAGE_VERSION", "latest")
	imageName := fmt.Sprintf("%s:%s", utils.EnvOrDefault("CLOUDFLARED_IMAGE_NAME", constants.CloudflaredImage), imageVersion)

	return applyAppsv1.DeploymentApplyConfiguration{
		TypeMetaApplyConfiguration: applyMetav1.TypeMetaApplyConfiguration{
			Kind:       pointer.String("Deployment"),
			APIVersion: pointer.String(appsv1.SchemeGroupVersion.String()),
		},
		ObjectMetaApplyConfiguration: &applyMetav1.ObjectMetaApplyConfiguration{
			Name:      pointer.String(CloudflaredDeploymentName),
			Namespace: pointer.String(constants.Namespace),
			Labels: map[string]string{
				"app":                                  CloudflaredDeploymentName,
				"applications.app.bytetrade.io/author": constants.AnnotationGroup,
				"applications.app.bytetrade.io/owner":  constants.Username,
			},
			Annotations: map[string]string{},
		},
		Spec: &applyAppsv1.DeploymentSpecApplyConfiguration{
			Replicas: pointer.Int32(CloudflareDeploymentReplicas),

			Selector: &applyMetav1.LabelSelectorApplyConfiguration{
				MatchLabels: map[string]string{
					"app": CloudflaredDeploymentName,
				},
			},
			Template: &applyCorev1.PodTemplateSpecApplyConfiguration{
				ObjectMetaApplyConfiguration: &applyMetav1.ObjectMetaApplyConfiguration{
					Labels: map[string]string{
						"app": CloudflaredDeploymentName,
					},
				},
				Spec: &applyCorev1.PodSpecApplyConfiguration{
					SchedulerName: pointer.String("default-scheduler"),
					Containers: []applyCorev1.ContainerApplyConfiguration{
						{
							Name:            pointer.String("tunnel"),
							Image:           pointer.String(imageName),
							ImagePullPolicy: &imagePullPolicy,
							Args: []string{
								"tunnel",
								"--no-autoupdate",
								"run",
								"--token",
								token,
							},
						},
					}, // end of pod containers
				}, //end of pod template spec
			}, // end of pod template
		}, // end of deployment spec
	}
}
