package v1alpha1

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"bytetrade.io/web3os/bfl/internal/log"
	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/apis"
	"bytetrade.io/web3os/bfl/pkg/apis/iam/v1alpha1/operator"
	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/app_service/v1"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/event/v1"
	"bytetrade.io/web3os/bfl/pkg/task"
	settingsTask "bytetrade.io/web3os/bfl/pkg/task/settings"
	"bytetrade.io/web3os/bfl/pkg/utils"
	"bytetrade.io/web3os/bfl/pkg/utils/certmanager"
	"github.com/emicklei/go-restful/v3"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"
	iamV1alpha2 "kubesphere.io/api/iam/v1alpha2"
)

type Handler struct {
	apis.Base
	appServiceClient *app_service.Client
	httpClient       *resty.Client
	eventClient      *event.Client
	backupService    *BackupService
}

func New() *Handler {
	return &Handler{
		appServiceClient: app_service.NewAppServiceClient(),
		httpClient:       resty.New().SetTimeout(30 * time.Second),
		eventClient:      event.NewClient(),
		backupService:    NewBackupService(),
	}
}

func (h *Handler) handleUnbindingUserZone(req *restful.Request, resp *restful.Response) {
	ctx, k8sClient := req.Request.Context(), runtime.NewKubeClient(req).Kubernetes()

	// delete user annotations
	userOp, err := operator.NewUserOperator()
	if err != nil {
		response.HandleError(resp, errors.Errorf("unbind user zone: %v", err))
		return
	}

	var terminusName string

	var user *iamV1alpha2.User
	user, err = userOp.GetUser("")
	if err != nil {
		response.HandleError(resp, errors.Errorf("unbind user zone: get user err, %v", err))
		return
	}

	if terminusName = userOp.GetTerminusName(user); terminusName != "" {
		cm := certmanager.NewCertManager(constants.TerminusName(terminusName))
		if err = cm.DeleteDNSRecord(); err != nil {
			log.Warnf("unbind user zone, delete dns record err, %v", err)
		}
	}

	// remove annotations
	userOp.UpdateUser(user, []func(*iamV1alpha2.User){
		func(u *iamV1alpha2.User) {
			delete(u.Annotations, constants.UserAnnotationTerminusNameKey)
			delete(u.Annotations, constants.UserAnnotationZoneKey)
			delete(u.Annotations, constants.EnableSSLTaskResultAnnotationKey)
		},
	})

	// remove frp-agent
	if err = k8sClient.AppsV1().Deployments(constants.Namespace).Delete(ctx,
		ReverseProxyAgentDeploymentName, metav1.DeleteOptions{}); err != nil {
		log.Warnf("unbind user zone, delete frp-agent err, %v", err)
	}

	// delete ssl config
	err = k8sClient.CoreV1().ConfigMaps(constants.Namespace).Delete(ctx,
		constants.NameSSLConfigMapName, metav1.DeleteOptions{})
	if err != nil {
		log.Warnf("unbind user zone, delete ssl configmap err, %v", err)
	}

	// delete re download cert cronjob
	err = k8sClient.BatchV1().CronJobs(constants.Namespace).Delete(ctx,
		certmanager.ReDownloadCertCronJobName, metav1.DeleteOptions{})
	if err != nil {
		log.Warnf("unbind user zone, delete cronjob err, %v", err)
	}

	log.Info("finish unbind user user zone")

	response.SuccessNoData(resp)
}

func (h *Handler) handleBindingUserZone(req *restful.Request, resp *restful.Response) {
	var post PostTerminusName
	err := req.ReadEntity(&post)
	if err != nil {
		response.HandleBadRequest(resp, errors.Errorf("binding zone: %v", err))
		return
	}

	op, err := operator.NewUserOperator()
	if err != nil {
		response.HandleBadRequest(resp, errors.Errorf("binding zone: %v", err))
		return
	}

	user, err := op.GetUser(constants.Username)
	if err != nil {
		response.HandleError(resp, errors.Errorf("binding user zone: get user err, %v", err))
		return
	}

	if v, ok := user.Annotations[constants.UserTerminusWizardStatus]; ok {
		if v != string(constants.WaitActivateVault) {
			response.HandleError(resp, errors.Errorf("user '%s' wizard status err, %s", user.Name, v))
			return
		}
	}

	domain, err := op.GetDomain()
	if err != nil {
		response.HandleError(resp, errors.Errorf("user '%s' get olares domain error, %v", user.Name, err))
		return
	}

	userPatches := []func(*iamV1alpha2.User){
		func(u *iamV1alpha2.User) {
			u.Annotations[constants.UserAnnotationTerminusNameKey] = string(constants.NewTerminusName(u.Name, domain))
		},
	}

	if post.JWSSignature != "" {
		userPatches = append(userPatches, func(u *iamV1alpha2.User) {
			u.Annotations[constants.UserCertManagerJWSToken] = post.JWSSignature
		})
	}

	if post.DID != "" {
		userPatches = append(userPatches, func(u *iamV1alpha2.User) {
			u.Annotations[constants.UserCertManagerDID] = post.DID
		})
	}

	userPatches = append(userPatches, func(u *iamV1alpha2.User) {
		u.Annotations[constants.UserTerminusWizardStatus] = string(constants.WaitActivateSystem)
	})

	if err = op.UpdateUser(user, userPatches); err != nil {
		response.HandleError(resp, errors.Errorf("binding user zone err:  %v", err))
		return
	}

	response.SuccessNoData(resp)
}

func (h *Handler) handleEnableHTTPs(req *restful.Request, resp *restful.Response) {
	ctx := req.Request.Context()

	var terminusName string
	userOp, err := operator.NewUserOperator()
	if err != nil {
		response.HandleError(resp, errors.Errorf("enable https: %v", err))
		return
	}
	user, err := userOp.GetUser("")
	if err != nil {
		response.HandleError(resp, errors.Errorf("enable https: %v", err))
		return
	}

	defer func() {
		if err != nil {
			if e := userOp.UpdateUser(user, []func(*iamV1alpha2.User){
				func(u *iamV1alpha2.User) {
					u.Annotations[constants.UserTerminusWizardStatus] = string(constants.NetworkActivateFailed)
					u.Annotations[constants.EnableSSLTaskResultAnnotationKey] = settingsTask.TaskResult{State: settingsTask.Failed}.String()
				},
			}); e != nil {
				klog.Errorf("update user err, %v", err)
			}
		}
	}()

	if e := userOp.UpdateUser(user, []func(*iamV1alpha2.User){
		func(u *iamV1alpha2.User) {
			u.Annotations[constants.UserTerminusWizardStatus] = string(constants.NetworkActivating)
		},
	}); e != nil {
		klog.Errorf("update user err, %v", err)
	}

	ErrAlreadyEnabled := errors.Errorf("is already enabled")
	ErrInProgress := errors.Errorf("in progress")
	err = func() error {

		if user != nil {
			terminusName = userOp.GetTerminusName(user)

			if terminusName == "" {
				return errors.Errorf("no olares name, please binding olares name first")
			}

			if userOp.AnnotationExists(user, constants.UserAnnotationZoneKey) {
				return ErrAlreadyEnabled
			}

			if v := userOp.GetUserAnnotation(user, constants.EnableSSLTaskResultAnnotationKey); v != "" {
				var t settingsTask.TaskResult

				err = json.Unmarshal([]byte(v), &t)
				if err != nil {
					return errors.Errorf("unmarshal task result, %v", err)
				}

				switch t.State {
				case settingsTask.Pending, settingsTask.Running:
					return ErrInProgress
				}
			}
		}
		return nil
	}()

	if err != nil {
		if err == ErrAlreadyEnabled || err == ErrInProgress {
			klog.Warning("duplicate ssl/enable requets, ", err)
			err = nil
			response.SuccessNoData(resp)
			return
		}

		response.HandleError(resp, errors.Errorf("enable https: %v", err))
		return
	}

	post := EnableHTTPSRequest{}
	req.ReadEntity(&post)

	log.Infow("enable https: post request,", "postBody", post)

	if (post.IP != "" && post.EnableReverseProxy) || (post.IP == "" && !post.EnableReverseProxy) {
		response.HandleError(resp, errors.New("bad request: one of public IP and reverse proxy should be selected"))
		return
	}

	reverseProxyConf := &ReverseProxyConfig{}
	if post.IP != "" {
		reverseProxyConf.IP = post.IP
	} else {
		reverseProxyConf, err = GetDefaultReverseProxyConfig(ctx)
		if err != nil {
			response.HandleError(resp, errors.Wrap(err, "failed to get default reverse proxy config"))
			return
		}
	}

	if err = reverseProxyConf.Check(); err != nil {
		response.HandleError(resp, errors.Wrap(err, "invalid reverse proxy configuration"))
		return
	}

	if err = reverseProxyConf.writeToReverseProxyConfigMap(ctx); err != nil {
		response.HandleError(resp, errors.Wrap(err, "failed to write reverse proxy configuration"))
		return
	}

	o := settingsTask.EnableHTTPSTaskOption{
		Name:                                terminusName,
		GenerateURL:                         fmt.Sprintf(constants.APIFormatCertGenerateRequest, terminusName),
		AccessToken:                         req.HeaderParameter(constants.AuthorizationTokenKey),
		ReverseProxyAgentDeploymentName:     ReverseProxyAgentDeploymentName,
		ReverseProxyAgentDeploymentReplicas: ReverseProxyAgentDeploymentReplicas,
		L4ProxyDeploymentName:               L4ProxyDeploymentName,
		L4ProxyDeploymentReplicas:           L4ProxyDeploymentReplicas,
	}

	// add global l4 proxy
	namespace := utils.EnvOrDefault("L4_PROXY_NAMESPACE", constants.OSSystemNamespace)
	serviceAccount := utils.EnvOrDefault("L4_PROXY_SERVICE_ACCOUNT", constants.L4ProxyServiceAccountName)

	k8sClient := runtime.NewKubeClient(req).Kubernetes()

	app, err := k8sClient.AppsV1().Deployments(namespace).Get(ctx, L4ProxyDeploymentName, metav1.GetOptions{})
	portStr := utils.EnvOrDefault("L4_PROXY_LISTEN", constants.L4ListenSSLPort)
	if (err != nil && apierrors.IsNotFound(err)) || app == nil {
		log.Warnf("get l4-proxy deployment err: %v, recreate it", err)

		var portInt int
		port, _ := strconv.Atoi(portStr)
		portInt = port

		// create proxy deployment
		proxyApply := NewL4ProxyDeploymentApplyConfiguration(namespace, serviceAccount, portInt)
		var createdProxy *appsv1.Deployment
		createdProxy, err = k8sClient.AppsV1().Deployments(namespace).Apply(ctx,
			&proxyApply, metav1.ApplyOptions{Force: true, FieldManager: constants.ApplyPatchFieldManager})
		if err != nil {
			response.HandleError(resp, errors.Errorf("enable https: apply l4 proxy deployment err, %v", err))
			return
		}
		log.Debugf("created l4 proxy deployment: %s", utils.PrettyJSON(createdProxy))
	}

	if err != nil {
		log.Errorf("get l4-proxy deployment err: %v", err)
		response.HandleError(resp, errors.Errorf("enable https: get l4 proxy deployment err, %v", err))
		return
	}

	o.L4ProxyNamespace = namespace

	log.Info("creating async task to enable https")

	enableHTTPSTask, err := settingsTask.NewEnableHTTPSTask(&o)
	if err != nil {
		response.HandleError(resp, errors.Errorf("enable https: new task err, %v", err))
		return
	}

	if err = enableHTTPSTask.UpdateTaskState(settingsTask.TaskResult{State: settingsTask.Running}); err != nil {
		response.HandleError(resp, errors.Errorf("enable https: update task state err, %v", err))
		return
	}

	task.LocalTaskQueue.Push("EnableHTTPS", enableHTTPSTask)
	response.SuccessNoData(resp)
}

func (h *Handler) handleChangeReverseProxyConfig(req *restful.Request, resp *restful.Response) {
	ctx := req.Request.Context()
	conf := &ReverseProxyConfig{}
	if err := req.ReadEntity(conf); err != nil {
		response.HandleError(resp, err)
		return
	}
	if err := conf.Check(); err != nil {
		response.HandleError(resp, errors.Wrap(err, "invalid reverse proxy config"))
		return
	}

	if err := conf.writeToReverseProxyConfigMap(ctx); err != nil {
		response.HandleError(resp, errors.Wrap(err, "failed to write reverse proxy config"))
		return
	}

	response.SuccessNoData(resp)
}

func (h *Handler) handleGetReverseProxyConfig(req *restful.Request, resp *restful.Response) {
	ctx := req.Request.Context()
	conf, err := GetReverseProxyConfig(ctx)
	if err != nil {
		response.HandleError(resp, errors.Wrap(err, "failed to get reverse proxy config"))
		return
	}
	response.Success(resp, conf)
}

func (h *Handler) handleGetDefaultReverseProxyConfig(req *restful.Request, resp *restful.Response) {
	ctx := req.Request.Context()
	conf, err := GetDefaultReverseProxyConfig(ctx)
	if err != nil {
		response.HandleError(resp, errors.Wrap(err, "failed to get the default reverse proxy config"))
		return
	}
	response.Success(resp, conf)
}

func (h *Handler) handleGetEnableHTTPSTaskState(req *restful.Request, resp *restful.Response) {
	name := req.Attribute(constants.UserContextAttribute).(string)
	t, err := settingsTask.GetEnableHTTPSTaskState(name)
	if err != nil {
		response.HandleError(resp, errors.Errorf("get enable https state: %v", err))
		return
	}
	response.Success(resp, t)
}

func (h *Handler) handleGetLauncherAccessPolicy(req *restful.Request, resp *restful.Response) {
	userOp, err := operator.NewUserOperator()
	if err != nil {
		response.HandleError(resp, errors.Errorf("get launcher access policy: new user operator err, %v", err))
		return
	}
	user, err := userOp.GetUser(constants.Username)
	if err != nil {
		response.HandleError(resp, errors.Errorf("get launcher access policy: get user err, %v", err))
		return
	}

	var accessLevel AccessLevel
	var allowCIDRs []string
	var authPolicy AuthPolicy

	err = func() error {
		level, err := userOp.GetLauncherAccessLevel(user)
		if err != nil {
			return errors.Errorf("no user access_level")
		}
		if level != nil {
			accessLevel = AccessLevel(*level)
		}
		allowCIDRs = userOp.GetLauncherAllowCIDR(user)

		authPolicy = AuthPolicy(userOp.GetLauncherAuthPolicy(user))
		if authPolicy == "" {
			authPolicy = DefaultAuthPolicy
		}
		return nil
	}()

	if err != nil {
		response.HandleError(resp, errors.Errorf("get launcher access policy: %v", err))
		return
	}

	response.Success(resp, LauncherAccessPolicy{AccessLevel: accessLevel, AllowCIDRs: allowCIDRs, AuthPolicy: authPolicy})
}

func (h *Handler) configDefaultAllowCIDR(req *restful.Request, level AccessLevel) []string {
	var allows []string

	switch level {
	case WorldWide, Public:
		allows = []string{"0.0.0.0/0"}
	case Private:
		allows = []string{"127.0.0.1/32", "192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}

		if external := utils.GetMyExternalIPAddr(); external != "" {
			allows = append(allows, external+"/32")
		}
	}
	return allows
}

func (h *Handler) handleUpdateLauncherAccessPolicy(req *restful.Request, resp *restful.Response) {
	var policy LauncherAccessPolicy
	req.ReadEntity(&policy)

	log.Infow("update launcher access policy", "policy", policy)

	if policy.AccessLevel == 0 {
		response.HandleError(resp, errors.New("update launcher access policy: no access level provieded"))
		return
	}

	if policy.AuthPolicy == "" {
		policy.AuthPolicy = DefaultAuthPolicy
	}

	err := func() error {
		userOp, err := operator.NewUserOperator()
		if err != nil {
			return errors.Errorf("new user operator err, %v", err)
		}
		user, err := userOp.GetUser(constants.Username)
		if err != nil {
			return errors.Errorf("get user err, %v", err)
		}

		currentAuthPolicy := userOp.GetLauncherAuthPolicy(user)

		cidrs := userOp.GetLauncherAllowCIDR(user)
		if reflect.DeepEqual(cidrs, policy.AllowCIDRs) {
			if currentAuthPolicy != string(policy.AuthPolicy) {
				if err = userOp.UpdateUser(user, []func(*iamV1alpha2.User){
					func(u *iamV1alpha2.User) {
						u.Annotations[constants.UserLauncherAuthPolicy] = string(policy.AuthPolicy)
					},
				}); err != nil {
					return errors.Errorf("update user err, %v", err)
				}
			}
			return nil
		}

		var ipCIDRs []string

		if len(policy.AllowCIDRs) == 0 {
			ipCIDRs = h.configDefaultAllowCIDR(req, policy.AccessLevel)
		} else {
			for _, cidr := range policy.AllowCIDRs {
				if !strings.Contains(cidr, "/") {
					return errors.Errorf("%q is invalid ip cidr, missing subnet mask, eg: '/24'", cidr)
				}
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					if err != nil {
						return errors.Errorf("parse cidr err, %v", err)
					}
				}
				ipCIDRs = append(ipCIDRs, ipNet.String())
			}
		}
		if policy.AccessLevel == Protected {
			if !utils.ListContains(ipCIDRs, DefaultPodsCIDR) {
				ipCIDRs = append(ipCIDRs, DefaultPodsCIDR)
			}
		}

		if err = userOp.UpdateUser(user, []func(*iamV1alpha2.User){
			func(u *iamV1alpha2.User) {
				u.Annotations[constants.UserLauncherAccessLevel] = fmt.Sprintf("%v", policy.AccessLevel)
				u.Annotations[constants.UserLauncherAllowCIDR] = strings.Join(ipCIDRs, ",")
				u.Annotations[constants.UserLauncherAuthPolicy] = string(policy.AuthPolicy)
			},
		}); err != nil {
			return errors.Errorf("update user err, %v", err)
		}
		return nil
	}()

	if err != nil {
		response.HandleError(resp, errors.Errorf("update launcher access policy: %v", err))
		return
	}

	response.SuccessNoData(resp)
}

func (h *Handler) handleGetPublicDomainAccessPolicy(req *restful.Request, resp *restful.Response) {
	userOp, err := operator.NewUserOperator()
	if err != nil {
		response.HandleError(resp, errors.Errorf("get public domain access policy: new user operator err, %v", err))
		return
	}
	user, err := userOp.GetUser(constants.Username)
	if err != nil {
		response.HandleError(resp, errors.Errorf("get public domain access policy: get user err, %v", err))
		return
	}

	var denyAllAnno string = userOp.GetDenyAllPolicy(user)

	var denyAll, _ = strconv.Atoi(denyAllAnno)

	response.Success(resp, PublicDomainAccessPolicy{DenyAll: denyAll}) //  AllowedDomains: strings.Split(allowedDomains, ",")
}

func (h *Handler) handleUpdatePublicDomainAccessPolicy(req *restful.Request, resp *restful.Response) {
	var policy PublicDomainAccessPolicy
	req.ReadEntity(&policy)

	log.Infow("update public domain access policy", "policy", policy)

	if policy.DenyAll < 0 || policy.DenyAll > 1 {
		response.HandleError(resp, errors.Errorf("update public domain access policy: deny all %d params invalid", policy.DenyAll))
		return
	}

	err := func() error {
		userOp, err := operator.NewUserOperator()
		if err != nil {
			return errors.Errorf("new user operator err, %v", err)
		}
		user, err := userOp.GetUser(constants.Username)
		if err != nil {
			return errors.Errorf("get user err, %v", err)
		}

		if err = userOp.UpdateUser(user, []func(*iamV1alpha2.User){
			func(u *iamV1alpha2.User) {
				u.Annotations[constants.UserDenyAllPolicy] = strconv.Itoa(policy.DenyAll)
			},
		}); err != nil {
			return errors.Errorf("update user err, %v", err)
		}
		return nil
	}()

	if err != nil {
		response.HandleError(resp, errors.Errorf("update public domain access policy: %v", err))
		return
	}

	response.SuccessNoData(resp)
}

func (h *Handler) handleUpdateLocale(req *restful.Request, resp *restful.Response) {
	var locale apis.PostLocale
	userOp, err := operator.NewUserOperator()
	if err != nil {
		response.HandleError(resp, errors.Errorf("update user locale err: new user operator err, %v", err))
		return
	}

	user, err := userOp.GetUser(constants.Username)
	if err != nil {
		response.HandleError(resp, errors.Errorf("update user locale err: get user err, %v", err))
		return
	}

	defer func() {
		if err != nil {
			if user.Annotations[constants.UserTerminusWizardStatus] != string(constants.Completed) {
				if e := userOp.UpdateUser(user, []func(*iamV1alpha2.User){
					func(u *iamV1alpha2.User) {
						u.Annotations[constants.UserTerminusWizardStatus] = string(constants.SystemActivateFailed)
					},
				}); e != nil {
					klog.Errorf("update user err, %v", err)
				}
			}
		}
	}()

	if user.Annotations[constants.UserTerminusWizardStatus] != string(constants.Completed) {
		err = userOp.UpdateUser(user, []func(*iamV1alpha2.User){
			func(u *iamV1alpha2.User) {
				u.Annotations[constants.UserTerminusWizardStatus] = string(constants.SystemActivating)
			},
		})

		if err != nil {
			klog.Errorf("update user err, %v", err)
			response.HandleError(resp, errors.Errorf("update user locale data error: %v", err))
			return
		}
	}

	err = req.ReadEntity(&locale)
	if err != nil {
		klog.Error("read request body error, ", err)
		response.HandleError(resp, errors.Errorf("update user locale data error: %v", err))
		return
	}

	err = func() error {
		if err = userOp.UpdateUser(user, []func(*iamV1alpha2.User){
			func(u *iamV1alpha2.User) {
				if locale.Language != "" {
					u.Annotations[constants.UserLanguage] = locale.Language
				}

				if locale.Location != "" {
					u.Annotations[constants.UserLocation] = locale.Location
				}

				if locale.Theme == "" {
					locale.Theme = "light"
				}
				u.Annotations[constants.UserTheme] = locale.Theme

				if u.Annotations[constants.UserTerminusWizardStatus] != string(constants.Completed) {
					u.Annotations[constants.UserTerminusWizardStatus] = string(constants.WaitActivateNetwork)
				}
			},
		}); err != nil {
			return errors.Errorf("update user err, %v", err)
		}
		return nil
	}()

	if err != nil {
		response.HandleError(resp, errors.Errorf("update user locale err: %v", err))
		return
	}

	response.SuccessNoData(resp)
}

func (h *Handler) handlerUpdateUserLoginBackground(req *restful.Request, resp *restful.Response) {
	var background struct {
		Background string `json:"background"`
	}

	err := req.ReadEntity(&background)
	if err != nil {
		klog.Error("read request body error, ", err)
		response.HandleError(resp, errors.Errorf("update user login background error: %v", err))
		return
	}

	userOp, err := operator.NewUserOperator()
	if err != nil {
		response.HandleError(resp, errors.Errorf("update user login background err: new user operator err, %v", err))
		return
	}

	user, err := userOp.GetUser(constants.Username)
	if err != nil {
		response.HandleError(resp, errors.Errorf("update user login background err: get user err, %v", err))
		return
	}

	err = userOp.UpdateUser(user, []func(*iamV1alpha2.User){
		func(u *iamV1alpha2.User) {
			u.Annotations[constants.UserLoginBackground] = background.Background
		},
	})

	if err != nil {
		klog.Errorf("update user err, %v", err)
		response.HandleError(resp, errors.Errorf("update user login background error: %v", err))
		return
	}

	response.SuccessNoData(resp)
}

func (h *Handler) handlerUpdateUserAvatar(req *restful.Request, resp *restful.Response) {
	var avatar struct {
		Avatar string `json:"avatar"`
	}

	err := req.ReadEntity(&avatar)
	if err != nil {
		klog.Error("read request body error, ", err)
		response.HandleError(resp, errors.Errorf("update user avatar error: %v", err))
		return
	}

	userOp, err := operator.NewUserOperator()
	if err != nil {
		response.HandleError(resp, errors.Errorf("update user avatar err: new user operator err, %v", err))
		return
	}

	user, err := userOp.GetUser(constants.Username)
	if err != nil {
		response.HandleError(resp, errors.Errorf("update user avatar err: get user err, %v", err))
		return
	}

	err = userOp.UpdateUser(user, []func(*iamV1alpha2.User){
		func(u *iamV1alpha2.User) {
			u.Annotations[constants.UserAvatar] = avatar.Avatar
		},
	})

	if err != nil {
		klog.Errorf("update user err, %v", err)
		response.HandleError(resp, errors.Errorf("update user avatar error: %v", err))
		return
	}

	response.SuccessNoData(resp)
}
