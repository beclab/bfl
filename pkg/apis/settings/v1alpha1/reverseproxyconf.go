package v1alpha1

import (
	"bytetrade.io/web3os/bfl/pkg/apis/iam/v1alpha1/operator"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils"
	"bytetrade.io/web3os/bfl/pkg/utils/certmanager"
	"bytetrade.io/web3os/bfl/pkg/utils/k8sutil"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/emicklei/go-restful"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	applyAppsv1 "k8s.io/client-go/applyconfigurations/apps/v1"
	applyCorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	applyMetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/pointer"
	iamV1alpha2 "kubesphere.io/api/iam/v1alpha2"
	"net"
	"net/http"
	"strconv"
	"time"
)

type ReverseProxyConfigurator struct {
	kubeClient   kubernetes.Interface
	userOp       *operator.UserOperator
	cm           certmanager.Interface
	user         *iamV1alpha2.User
	terminusName string
}

type ReverseProxyConfig struct {
	FRPConfig
	IP                     string `json:"ip"`
	EnableCloudFlareTunnel bool   `json:"enable_cloudflare_tunnel"`
	EnableFRP              bool   `json:"enable_frp"`
}

type FRPConfig struct {
	FRPServer     string `json:"frp_server"`
	FRPPort       int    `json:"frp_port"`
	FRPAuthMethod string `json:"frp_auth_method"`
	FRPAuthToken  string `json:"frp_auth_token"`
}

var (
	FRPOptionServer     string = "server"
	FRPOptionPort       string = "port"
	FRPOptionAuthMethod string = "auth-method"
	FRPOptionAuthToken  string = "auth-token"
	FRPOptionUserName   string = "username"
	FRPAuthMethodJWS    string = "jws"
	FRPAuthMethodToken  string = "token"

	ReverseProxyConfigKeyPublicIP         = "public_ip"
	ReverseProxyConfigKeyCloudFlareEnable = "cloudflare.enable"
	ReverseProxyConfigKeyFRPEnable        = "frp.enable"
	ReverseProxyConfigValueEnabled        = "1"
	ReverseProxyConfigKeyFRPServer        = "frp.server"
	ReverseProxyConfigKeyFRPPort          = "frp.port"
	ReverseProxyConfigKeyFRPAuthMethod    = "frp.auth_method"
	ReverseProxyConfigKeyFRPAuthToken     = "frp.auth_token"
)

func NewReverseProxyConfigurator() (*ReverseProxyConfigurator, error) {
	userOp, err := operator.NewUserOperator()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user operator")
	}
	user, err := userOp.GetUser("")
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user")
	}
	terminusName := userOp.GetTerminusName(user)
	if terminusName == "" {
		return nil, errors.New("terminus name of user is empty")
	}
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get in-cluster config")
	}
	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get kubernetes client")
	}
	cm := certmanager.NewCertManager(constants.TerminusName(terminusName))
	return &ReverseProxyConfigurator{
		kubeClient:   kubeClient,
		userOp:       userOp,
		cm:           cm,
		user:         user,
		terminusName: terminusName,
	}, nil
}

func (configurator *ReverseProxyConfigurator) CheckConfig(conf *ReverseProxyConfig) error {
	if conf == nil {
		return errors.New("nil ReverseProxyConfig")
	}
	if conf.EnableCloudFlareTunnel {
		if conf.IP != "" || conf.EnableFRP {
			return errors.New("only one of public IP, FRP, or CloudFlare tunnel should be selected")
		}
		return nil
	}
	if conf.EnableFRP {
		if conf.IP != "" {
			return errors.New("only one of public IP, FRP, or CloudFlare tunnel should be selected")
		}
		if conf.FRPServer == "" {
			return errors.New("FRP server is not provided")
		}
		if conf.FRPAuthMethod == FRPAuthMethodToken && conf.FRPAuthToken == "" {
			return errors.New("FRP auth method is selected as token but no token is provided")
		}
		return nil
	}
	if conf.IP == "" {
		return errors.New("one of public IP, FRP, or CloudFlare tunnel should be selected")
	}
	return nil
}

// configureDNS configures DNS records
// and also update the corresponding annotations on the user resource
func (configurator *ReverseProxyConfigurator) configureDNS(publicIP, localIP, publicCName string) error {
	if publicIP != "" {
		if err := configurator.cm.AddDNSRecord(&publicIP, nil, nil); err != nil {
			return errors.Wrap(err, "failed to configure DNS record for public IP")
		}
		if err := configurator.userOp.UpdateAnnotation(configurator.user, constants.UserAnnotationPublicDomainIp, publicIP); err != nil {
			return errors.Wrap(err, "failed to update PublicDomainIP annotation")
		}
	}
	if localIP != "" {
		if err := configurator.cm.AddDNSRecord(nil, &localIP, nil); err != nil {
			return errors.Wrap(err, "failed to configure DNS record for local IP")
		}
		if err := configurator.userOp.UpdateAnnotation(configurator.user, constants.UserAnnotationLocalDomainIp, localIP); err != nil {
			return errors.Wrap(err, "failed to update LocalDomainIP annotation")
		}
	}
	if publicCName != "" {
		if err := configurator.cm.AddDNSRecord(nil, nil, &publicCName); err != nil {
			return errors.Wrap(err, "failed to configure DNS record for public CName")
		}
		if err := configurator.userOp.UpdateAnnotation(configurator.user, constants.UserAnnotationPublicDomainIp, publicCName); err != nil {
			return errors.Wrap(err, "failed to update PublicDomainIP annotation")
		}
	}
	// switched from public IP or FRP to cloudflare tunnel
	if publicIP == "" && publicCName == "" {
		return configurator.userOp.UpdateAnnotation(configurator.user, constants.UserAnnotationPublicDomainIp, "")
	}
	return nil
}

func (configurator *ReverseProxyConfigurator) Configure(ctx context.Context, conf *ReverseProxyConfig) (err error) {
	var publicIP, localIP, publicCName string
	defer func() {
		if err != nil {
			return
		}
		err = errors.Wrap(configurator.configureDNS(publicIP, localIP, publicCName), "failed to configure DNS")
		err = errors.Wrap(conf.writeToReverseProxyConfigMap(ctx), "failed to write reverse proxy config data")
	}()
	localL4ProxyIP, err := k8sutil.GetL4ProxyNodeIP(ctx, 30*time.Second)
	if err != nil {
		return errors.Wrap(err, "failed to get local l4 proxy ip")
	}
	localIP = *localL4ProxyIP
	localPort := utils.EnvOrDefault("L4_PROXY_LISTEN", constants.L4ListenSSLPort)

	if conf.IP != "" {
		publicIP = conf.IP
		// delete the reverse proxy agent, if existing
		err := configurator.kubeClient.AppsV1().Deployments(constants.Namespace).Delete(ctx, ReverseProxyAgentDeploymentName, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return errors.Wrap(err, "failed to delete existing reverse proxy agent")
		}
		return errors.Wrap(
			configurator.userOp.UpdateAnnotation(configurator.user, constants.UserAnnotationReverseProxyType, constants.ReverseProxyTypeNone),
			"failed to set reverse proxy type annotation to user")
	}

	reverseProxyDeployment := newDefaultReverseProxyAgentDeploymentApplyConfiguration()
	if conf.EnableFRP {
		if net.ParseIP(conf.FRPServer) != nil {
			publicIP = conf.FRPServer
		} else {
			publicCName = conf.FRPServer
		}
		setReverseProxyAgentDeploymentToFRP(reverseProxyDeployment, conf.FRPConfig)
		if err := configurator.userOp.UpdateAnnotation(configurator.user, constants.UserAnnotationReverseProxyType, constants.ReverseProxyTypeFRP); err != nil {
			return errors.Wrap(err, "failed to set reverse proxy type annotation to user")
		}
	} else if conf.EnableCloudFlareTunnel {
		// get cloudflare token
		jws := configurator.userOp.GetUserAnnotation(configurator.user, constants.UserCertManagerJWSToken)
		if jws == "" {
			return errors.New("no jws token found in user annotation")
		}
		req := TunnelRequest{
			Name:    configurator.terminusName,
			Service: fmt.Sprintf("https://%s:%s", localIP, localPort),
		}
		res, err := resty.New().SetTimeout(30 * time.Second).
			SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).R().
			SetHeaders(map[string]string{
				restful.HEADER_ContentType: restful.MIME_JSON,
				restful.HEADER_Accept:      restful.MIME_JSON,
				"Authorization":            "Bearer " + jws,
			}).
			SetBody(req).
			SetResult(&TunnelResponse{}).
			Post("https://terminus-dnsop.snowinning.com/tunnel")
		if err != nil {
			return errors.Wrap(err, "failed to request cloudflare tunnel api")
		}
		if res.StatusCode() != http.StatusOK {
			return fmt.Errorf("error response from cloudflare tunnel api: %s", res.Body())
		}
		responseData := res.Result().(*TunnelResponse)
		if !responseData.Success || responseData.Data == nil || responseData.Data.Token == "" {
			return fmt.Errorf("error response from cloudflare tunnel api: %v", responseData)
		}
		setReverseProxyAgentDeploymentToCloudFlare(reverseProxyDeployment, responseData.Data.Token)
		if err := configurator.userOp.UpdateAnnotation(configurator.user, constants.UserAnnotationReverseProxyType, constants.ReverseProxyTypeCloudflare); err != nil {
			return errors.Wrap(err, "failed to set reverse proxy type annotation to user")
		}
	}
	_, err = configurator.kubeClient.AppsV1().Deployments(constants.Namespace).Apply(ctx,
		reverseProxyDeployment, metav1.ApplyOptions{Force: true, FieldManager: constants.ApplyPatchFieldManager})
	if err != nil {
		return errors.Wrap(err, "failed to apply reverse proxy agent")
	}
	return nil
}

func newDefaultReverseProxyAgentDeploymentApplyConfiguration() *applyAppsv1.DeploymentApplyConfiguration {
	imageVersion := utils.EnvOrDefault("REVERSE_PROXY_AGENT_IMAGE_VERSION", constants.ReverseProxyAgentImageVersion)
	imageName := fmt.Sprintf("%s:%s", utils.EnvOrDefault("REVERSE_PROXY_AGENT_IMAGE_NAME", constants.ReverseProxyAgentImage), imageVersion)
	imagePullPolicy := corev1.PullIfNotPresent

	return &applyAppsv1.DeploymentApplyConfiguration{
		TypeMetaApplyConfiguration: applyMetav1.TypeMetaApplyConfiguration{
			Kind:       pointer.String("Deployment"),
			APIVersion: pointer.String(appsv1.SchemeGroupVersion.String()),
		},
		ObjectMetaApplyConfiguration: &applyMetav1.ObjectMetaApplyConfiguration{
			Name:      pointer.String(ReverseProxyAgentDeploymentName),
			Namespace: pointer.String(constants.Namespace),
			Labels: map[string]string{
				"app":                                  ReverseProxyAgentDeploymentName,
				"applications.app.bytetrade.io/author": constants.AnnotationGroup,
				"applications.app.bytetrade.io/owner":  constants.Username,
			},
		},
		Spec: &applyAppsv1.DeploymentSpecApplyConfiguration{
			Replicas: pointer.Int32(ReverseProxyAgentDeploymentReplicas),

			Selector: &applyMetav1.LabelSelectorApplyConfiguration{
				MatchLabels: map[string]string{
					"app": ReverseProxyAgentDeploymentName,
				},
			},
			Template: &applyCorev1.PodTemplateSpecApplyConfiguration{
				ObjectMetaApplyConfiguration: &applyMetav1.ObjectMetaApplyConfiguration{
					Labels: map[string]string{
						"app": ReverseProxyAgentDeploymentName,
					},
				},
				Spec: &applyCorev1.PodSpecApplyConfiguration{
					SchedulerName:      pointer.String("default-scheduler"),
					ServiceAccountName: pointer.String("bytetrade-controller"),
					Containers: []applyCorev1.ContainerApplyConfiguration{
						{
							Name:            pointer.String("agent"),
							Image:           pointer.String(imageName),
							ImagePullPolicy: &imagePullPolicy,
						},
					},
				},
			},
		},
	}
}

func setEnvToReverseProxyAgentDeployment(deployConf *applyAppsv1.DeploymentApplyConfiguration, key, val string) {
	deployConf.Spec.Template.Spec.Containers[0].Env = append(
		deployConf.Spec.Template.Spec.Containers[0].Env,
		applyCorev1.EnvVarApplyConfiguration{Name: &key, Value: &val})
}

func setArgsToReverseProxyAgentDeployment(deployConf *applyAppsv1.DeploymentApplyConfiguration, args []string) {
	deployConf.Spec.Template.Spec.Containers[0].Args = args
}

func setReverseProxyAgentDeploymentToFRP(deployConf *applyAppsv1.DeploymentApplyConfiguration, frpConf FRPConfig) {
	setEnvToReverseProxyAgentDeployment(deployConf, ReverseProxyAgentSelectEnvKey, ReverseProxyAgentSelectFRPEnvVal)
	args := []string{utils.DashedOption(FRPOptionServer), frpConf.FRPServer, utils.DashedOption(FRPOptionUserName), constants.Username}
	if frpConf.FRPPort != 0 {
		args = append(args, utils.DashedOption(FRPOptionPort), strconv.Itoa(frpConf.FRPPort))
	}
	if frpConf.FRPAuthMethod != "" {
		args = append(args, utils.DashedOption(FRPOptionAuthMethod), frpConf.FRPAuthMethod)
		if frpConf.FRPAuthMethod == FRPAuthMethodToken {
			args = append(args, utils.DashedOption(FRPOptionAuthToken), frpConf.FRPAuthToken)
		}
	}
	setArgsToReverseProxyAgentDeployment(deployConf, args)
}

func setReverseProxyAgentDeploymentToCloudFlare(deployConf *applyAppsv1.DeploymentApplyConfiguration, token string) {
	setEnvToReverseProxyAgentDeployment(deployConf, ReverseProxyAgentSelectEnvKey, ReverseProxyAgentSelectCloudFlareEnvVal)
	setArgsToReverseProxyAgentDeployment(deployConf, []string{"tunnel", "run", "--token", token})
}

func (conf *ReverseProxyConfig) readFromReverseProxyConfigMapData(cmData map[string]string) error {
	conf.IP = cmData[ReverseProxyConfigKeyPublicIP]
	if cmData[ReverseProxyConfigKeyCloudFlareEnable] == ReverseProxyConfigValueEnabled {
		conf.EnableCloudFlareTunnel = true
		// don't break circuit here or at the above public ip logic
		// because the validity check will be done by the configurator
		// this method is only meant for parsing
	}
	if cmData[ReverseProxyConfigKeyFRPEnable] == ReverseProxyConfigValueEnabled {
		conf.EnableFRP = true
		conf.FRPServer = cmData[ReverseProxyConfigKeyFRPServer]
		if portStr := cmData[ReverseProxyConfigKeyFRPPort]; portStr != "" {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return errors.Wrapf(err, "invalid frp port %s", portStr)
			}
			conf.FRPPort = port
		}
		conf.FRPAuthMethod = cmData[ReverseProxyConfigKeyFRPAuthMethod]
		conf.FRPAuthToken = cmData[ReverseProxyConfigKeyFRPAuthToken]
	}
	return nil
}

func (conf *ReverseProxyConfig) generateReverseProxyConfigMapData() map[string]string {
	cmData := make(map[string]string)
	cmData[ReverseProxyConfigKeyPublicIP] = conf.IP
	if conf.EnableCloudFlareTunnel {
		cmData[ReverseProxyConfigKeyCloudFlareEnable] = ReverseProxyConfigValueEnabled
	}
	if conf.EnableFRP {
		cmData[ReverseProxyConfigKeyFRPEnable] = ReverseProxyConfigValueEnabled
		cmData[ReverseProxyConfigKeyFRPServer] = conf.FRPServer
		if conf.FRPPort != 0 {
			cmData[ReverseProxyConfigKeyFRPPort] = strconv.Itoa(conf.FRPPort)
		}
		cmData[ReverseProxyConfigKeyFRPAuthMethod] = conf.FRPAuthMethod
		cmData[ReverseProxyConfigKeyFRPAuthToken] = conf.FRPAuthToken
	}
	return cmData
}

func GetDefaultReverseProxyConfig(ctx context.Context) (*ReverseProxyConfig, error) {
	configData, err := k8sutil.GetConfigMapData(ctx, constants.OSSystemNamespace, constants.DefaultReverseProxyConfigMapName)
	if err != nil {
		return nil, errors.Wrap(err, "error getting configmap")
	}
	conf := &ReverseProxyConfig{}
	if err := conf.readFromReverseProxyConfigMapData(configData); err != nil {
		return nil, errors.Wrap(err, "error parsing default reverse proxy config data")
	}
	return conf, nil
}

func GetReverseProxyConfig(ctx context.Context) (*ReverseProxyConfig, error) {
	configData, err := k8sutil.GetConfigMapData(ctx, constants.Namespace, constants.ReverseProxyConfigMapName)
	if err != nil {
		return nil, errors.Wrap(err, "error getting configmap")
	}
	conf := &ReverseProxyConfig{}
	if err := conf.readFromReverseProxyConfigMapData(configData); err != nil {
		return nil, errors.Wrap(err, "error parsing reverse proxy config data")
	}
	return conf, nil
}

func (conf *ReverseProxyConfig) writeToReverseProxyConfigMap(ctx context.Context) error {
	cmData := conf.generateReverseProxyConfigMapData()
	err := k8sutil.WriteConfigMapData(ctx, constants.Namespace, constants.ReverseProxyConfigMapName, cmData)
	return errors.Wrap(err, "error writing configmap")
}
