package constants

import (
	"fmt"
	"strings"
)

var (
	// Username current userspace username
	Username string

	APIServerListenAddress string

	// Namespace BFL owner namespace
	Namespace string

	KubeSphereAPIHost string

	KubeSphereAPIScheme = "http"

	AuthorizationTokenKey = "X-Authorization"

	UserAppDataPath = "./appdata/launcher" // user app data pvc

	UserContextAttribute = "UserName"

	KubeSphereNamespace = "kubesphere-system"

	KubeSphereConfigName = "kubesphere-config"

	KubeSphereClientID = "kubesphere"

	KubeSphereClientSecret = "kubesphere"

	AnnotationUserCreator = "kubesphere.io/creator"

	KubeSphereCacheRedisHost = "redis.kubesphere-system.svc"

	KubeSphereCacheRedisPort = 6379

	KubeSphereCacheRedisDB = 0

	KubeSphereRedisSecretName     = "redis-secret"
	UserAnnotationLimitsCpuKey    = "bytetrade.io/user-cpu-limit"
	UserAnnotationLimitsMemoryKey = "bytetrade.io/user-memory-limit"

	MyAppsIsLocalKey = "my-apps-is-local"
	FrpServer        string
)

var (
	KubeSphereJwtKey []byte

	// RequestURLWhiteList api url white list, no token authentication
	RequestURLWhiteList = []string{
		"/bfl/iam/v1alpha1/login",
		"/bfl/iam/v1alpha1/validate",
		"/bfl/iam/v1alpha1/refresh-token",
		"/bfl/apidocs.json",
		"/bfl/backend/v1/",
		"/bfl/callback/v1alpha1/backup/",
		"/bfl/info/v1/",
		"/bfl/datastore/v1alpha1/",
	}
)

var (
	IndexAppEndpoint = "http://profile-service.user-space-%s.svc.cluster.local:3000"

	AppListenFromPort int32 = 8086

	AppPortNamePrefix = "app-"

	BFLServiceName string

	IsNatted bool
)

var (
	NameBindAPIHost = "frp.snowinning.com"

	nameBindAPIPrefix = "https://terminus-cert.snowinning.com"

	nameDNSAPIPrefix = "https://terminus-dnsop.snowinning.com"

	NameBindAPICertGenerateFormat = nameBindAPIPrefix + "/generate?" + nameParamters

	NameBandAPICertGenerateStatusFormat = nameBindAPIPrefix + "/status?" + nameParamters

	NameBindAPICertDownloadFormat = nameBindAPIPrefix + "/download?" + nameParamters

	DNSAPIAddDomainRecord = nameDNSAPIPrefix + "/adddnsrecord"

	DNSAPIDeleteDomainRecordFormat = nameDNSAPIPrefix + "/deldnsrecord?" + nameParamters

	DNSAPIAddCustomDomainOnCloudflare = nameDNSAPIPrefix + "/customhostname"

	DNSAPICheckCustomDomainCnameStatus = nameDNSAPIPrefix + "/checkcname"

	NameSSLConfigMapName = "zone-ssl-config"

	nameParamters = "name=%s"
)

var (
	AnnotationGroup = "bytetrade.io"

	UserAnnotationTerminusNameKey = fmt.Sprintf("%s/terminus-name", AnnotationGroup)

	UserAnnotationZoneKey = fmt.Sprintf("%s/zone", AnnotationGroup)

	UserAnnotationUninitialized = fmt.Sprintf("%s/uninitialized", AnnotationGroup)

	UserAnnotationOwnerRole = fmt.Sprintf("%s/owner-role", AnnotationGroup)

	UserAnnotationIsEphemeral = fmt.Sprintf("%s/is-ephemeral", AnnotationGroup)

	EnableSSLTaskResultAnnotationKey = fmt.Sprintf("%s/task-enable-ssl", AnnotationGroup)

	L4ListenSSLPort = "443"

	L4ProxyNamespace = "os-system" // "kubesphere-system"

	L4ProxySSLPort = 444

	L4ProxyServiceAccountName = "os-internal" // "kubesphere"

	L4ProxyImage = "beclab/l4-bfl-proxy"
	FrpcImage    = "beclab/frpc"

	ApplyPatchFieldManager = "application/apply-patch"

	UserspaceNameFormat = "user-space-%s"

	UserLauncherAccessLevel = fmt.Sprintf("%s/launcher-access-level", AnnotationGroup)

	UserLauncherAllowCIDR = fmt.Sprintf("%s/launcher-allow-cidr", AnnotationGroup)

	UserLauncherAuthPolicy = fmt.Sprintf("%s/launcher-auth-policy", AnnotationGroup)

	UserCertManagerJWSToken = fmt.Sprintf("%s/jws-token-signature", AnnotationGroup)

	UserCertManagerDID = fmt.Sprintf("%s/user-did", AnnotationGroup)

	UserDenyAllPolicy = fmt.Sprintf("%s/deny-all", AnnotationGroup)

	UserAllowedDomainAccessPolicy = fmt.Sprintf("%s/deny-all-public-update", AnnotationGroup)

	UserLanguage = fmt.Sprintf("%s/language", AnnotationGroup)

	UserLocation = fmt.Sprintf("%s/location", AnnotationGroup)

	UserTerminusWizardStatus = fmt.Sprintf("%s/wizard-status", AnnotationGroup)

	UserAvatar = fmt.Sprintf("%s/avatar", AnnotationGroup)

	UserLoginBackground = fmt.Sprintf("%s/login-background", AnnotationGroup)
)

var (
	UserAnnotationPublicDomainIp = fmt.Sprintf("%s/public-domain-ip", AnnotationGroup)

	UserAnnotationLocalDomainIp = fmt.Sprintf("%s/local-domain-ip", AnnotationGroup)

	FrpDeploymentName = "frp-agent"

	FrpServers = []string{
		"frp-east-1.snowinning.com",
		"frp-hk.snowinning.com",
		"frp.snowinning.com",
		"frp-new.snowinning.com",
	}
)

var (
	RolePlatformAdmin = "platform-admin"

	RoleWorkspacesManager = "workspaces-manager"
)

var (
	ApplicationAuthorizationLevel = "authorizationLevel"

	ApplicationCustomDomain = "customDomain"

	ApplicationThirdLevelDomain = "third_level_domain"

	ApplicationThirdPartyDomain = "third_party_domain"

	ApplicationThirdPartyDomainCert = "ssl_config"

	ApplicationThirdPartyDomainCertKeySuffix = "-domain-ssl-config"

	ApplicationCustomDomainCnameTarget       = "cname_target"
	ApplicationCustomDomainCnameTargetStatus = "cname_target_status"
	ApplicationCustomDomainCnameStatus       = "cname_status"

	ApplicationCustomDomainCnameSslStatus      = "cname_ssl_status"
	ApplicationCustomDomainCnameHostnameStatus = "cname_hostname_status"
)

type CustomDomain int

const (
	CustomDomainIgnore CustomDomain = iota
	CustomDomainAdd
	CustomDomainUpdate
	CustomDomainDelete
	CustomDomainCheck
)

const (
	CloudFlareCnameStatusDefault string = "default"
	CloudFlareCnameStatusError   string = "error"
)

const (
	CustomDomainCnameStatusEmpty   = ""
	CustomDomainCnameStatusSet     = "set"     //
	CustomDomainCnameStatusNotset  = "unset"   // notset
	CustomDomainCnameStatusPending = "pending" // pending
	CustomDomainCnameStatusActive  = "active"  // active
	CustomDomainCnameStatusNone    = "none"    // none
	CustomDomainCnameStatusTimeout = "timeout" // timeout
	CustomDomainCnameStatusError   = "error"   // error
)

var SystemReservedKeyWords = []string{
	"user",
	"system",
	"space",
	"default",
	"os",
	"kubesphere",
	"kube",
	"kubekey",
	"kubernetes",
	"gpu",
	"tapr",
	"bfl",
	"bytetrade",
	"project",
	"pod",
}

// format: user-name@domain-name
type TerminusName string

func (s TerminusName) UserName() string {
	return s.UserAndDomain()[0]
}

func NewTerminusName(username, domainname string) TerminusName {
	return TerminusName(fmt.Sprintf("%s@%s", username, domainname))
}

func (s TerminusName) UserAndDomain() []string {
	return strings.Split(string(s), "@")
}

func (s TerminusName) UserZone() string {
	return strings.Join(s.UserAndDomain(), ".")
}

type WizardStatus string

const (
	WaitActivateVault     WizardStatus = "wait_activate_vault"
	WaitActivateSystem    WizardStatus = "wait_activate_system"
	SystemActivating      WizardStatus = "system_activating"
	WaitActivateNetwork   WizardStatus = "wait_activate_network"
	SystemActivateFailed  WizardStatus = "system_activate_failed"
	NetworkActivating     WizardStatus = "network_activating"
	NetworkActivateFailed WizardStatus = "network_activate_failed"
	WaitResetPassword     WizardStatus = "wait_reset_password"
	Completed             WizardStatus = "completed"
)
