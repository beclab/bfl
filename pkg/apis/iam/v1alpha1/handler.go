package v1alpha1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"bytetrade.io/web3os/bfl/internal/log"
	"bytetrade.io/web3os/bfl/pkg/api"
	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/apis/iam/v1alpha1/operator"
	"bytetrade.io/web3os/bfl/pkg/apis/iam/v1alpha1/templates"
	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/app_service/v1"
	v1alpha1client "bytetrade.io/web3os/bfl/pkg/client/clientset/v1alpha1"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/event/v1"
	"bytetrade.io/web3os/bfl/pkg/lldap"
	"bytetrade.io/web3os/bfl/pkg/task"
	"bytetrade.io/web3os/bfl/pkg/task/settings"
	"bytetrade.io/web3os/bfl/pkg/utils"
	"bytetrade.io/web3os/bfl/pkg/utils/httpclient"
	"github.com/beclab/lldap-client/pkg/auth"

	apiRuntime "bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"github.com/asaskevich/govalidator"
	"github.com/emicklei/go-restful/v3"
	"github.com/pkg/errors"
	"go.uber.org/atomic"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	applyCorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/pointer"
	iamV1alpha2 "kubesphere.io/api/iam/v1alpha2"
	"kubesphere.io/kubesphere/pkg/client/clientset/versioned/typed/iam/v1alpha2"
)

const (
	kubeSphereAPIToken = "/oauth/token"

	kubeSphereAPILogout = "/oauth/logout"

	minPodNumPerUser      = 25
	reservedPodNumForUser = 10
)

var defaultGlobalRoles = []string{
	constants.RolePlatformAdmin,
	// "platform-regular",    useless role
	// "users-manager",
	constants.RoleWorkspacesManager,
}

type Handler struct {
	eventClient       *event.Client
	userCreatingCount *atomic.Int32
}

type CommonTask struct {
	task.LocalTaskInterface
	execFunc func()
}

func (ct *CommonTask) Execute() {
	ct.execFunc()
}

func New() *Handler {
	return &Handler{
		eventClient:       event.NewClient(),
		userCreatingCount: &atomic.Int32{},
	}
}

func (h *Handler) newIamClient(req *restful.Request) v1alpha2.IamV1alpha2Interface {
	return runtime.NewKubeClient(req).KubeSphere().IamV1alpha2()
}

func (h *Handler) handleUserLogin(req *restful.Request, resp *restful.Response) {
	var u UserPassword
	err := req.ReadEntity(&u)
	if err != nil {
		response.HandleBadRequest(resp, errors.Errorf("login user, read entity: %v", err))
		return
	}

	log.Infow("read user entity", "userPassword", u)

	if u.UserName != constants.Username {
		response.HandleBadRequest(resp, errors.New("login user: mismatch input username and userspace"))
		return
	}

	data := map[string]string{
		"username":      u.UserName,
		"password":      u.Password,
		"client_id":     constants.KubeSphereClientID,
		"client_secret": constants.KubeSphereClientSecret,
		"grant_type":    "password",
	}

	token, code, err := RequestToken("", data)
	if err != nil {
		// response.HandleError(resp, errors.Errorf("login user, request token: %v", err))
		resp.WriteHeaderAndEntity(http.StatusOK, response.Header{
			Code:    code,
			Message: err.Error(),
		})
		return
	}
	response.Success(resp, token)
}

func (h *Handler) handleRefreshToken(req *restful.Request, resp *restful.Response) {
	var pt PostRefreshToken
	err := req.ReadEntity(&pt)
	if err != nil {
		response.HandleBadRequest(resp, errors.Errorf("refresh token: read entity err, %v", err))
		return
	}

	if pt.Token == "" {
		response.HandleBadRequest(resp, errors.New("refresh token: the token field must be provided"))
		return
	}

	log.Infow("refresh token, read input", "refreshToken", pt)

	newToken, err := auth.Refresh("http://lldap-service.os-framework:17170", pt.Token)
	if err != nil {
		resp.WriteHeaderAndEntity(http.StatusOK, response.Header{
			Code:    -1,
			Message: err.Error(),
		})
		return
	}

	log.Infow("refresh token: generated new", "accessToken", newToken)

	response.Success(resp, newToken)
}

func (h *Handler) handleUserLogOut(req *restful.Request, resp *restful.Response) {
	token := req.HeaderParameter(constants.AuthorizationTokenKey)

	_url := fmt.Sprintf("%s://%s%s", constants.KubeSphereAPIScheme, constants.KubeSphereAPIHost, kubeSphereAPILogout)
	c := httpclient.New(&httpclient.Option{
		Debug:   true,
		Timeout: 15 * time.Second,
	})

	c.SetHeaders(map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
		"content-type":  "application/json",
		"x-client-ip":   utils.RemoteIp(req.Request),
	})

	respLogout, err := c.R().Get(_url)
	if err != nil {
		response.HandleError(resp, errors.Errorf("logout user: %v", err))
		return
	}

	respLogoutBytes := respLogout.Body()

	log.Debugw("request user logout", "requestUrl", _url,
		"requestHeader", c.Header,
		"responseCode", respLogout.StatusCode(),
		"responseBody", string(respLogoutBytes))

	if respLogout.StatusCode() != http.StatusOK {
		var e UnauthorizedError
		if err = json.Unmarshal(respLogoutBytes, &e); err == nil {
			response.HandleUnauthorized(resp, errors.Errorf("logout user: unmarshal response err: %v", e.Message))
			return
		}
		response.HandleUnauthorized(resp, errors.Errorf("logout user: %v", string(respLogoutBytes)))
		return
	}

	var v struct {
		Message string `json:"message"`
	}
	if err = json.Unmarshal(respLogoutBytes, &v); err == nil &&
		v.Message == response.SuccessMsg {

		// send event to desktop
		if err := h.eventClient.CreateEvent("settings-event", "user logout", map[string]string{
			"user": constants.Username,
		}); err != nil {
			log.Errorf("send user logout event to desktop error, %v", err)
		}

		response.SuccessNoData(resp)
		return
	}
	response.HandleInternalError(resp, errors.New(response.UnexpectedError))
}

func (h *Handler) getRolesByUserName(name string, ctx context.Context, iamClient v1alpha2.IamV1alpha2Interface) ([]string, error) {
	globalRoleBindings, err := iamClient.GlobalRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var roles = sets.NewString()

	for _, binding := range globalRoleBindings.Items {
		for _, subject := range binding.Subjects {
			if subject.Name == name {
				roles.Insert(binding.RoleRef.Name)
			}
		}
	}
	return roles.List(), nil
}

func (h *Handler) listUsers(ctx context.Context, c v1alpha2.IamV1alpha2Interface) ([]iamV1alpha2.User, error) {
	users, err := c.Users().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return users.Items, nil
}

func (h *Handler) handleListUsers(req *restful.Request, resp *restful.Response) {
	ctx, iamClient := req.Request.Context(), h.newIamClient(req)

	users, err := h.listUsers(ctx, iamClient)
	if err != nil {
		if apierrors.IsNotFound(err) {
			response.Success(resp, []any{})
			return
		}
		response.HandleError(resp, errors.Errorf("list users: %v", err))
		return
	}

	usersInfo := make([]UserInfo, 0)

	for _, user := range users {
		var roles []string

		roles, err = h.getRolesByUserName(user.Name, ctx, iamClient)
		if err != nil {
			break
		}

		u := UserInfo{
			UID:               string(user.UID),
			Name:              user.Name,
			DisplayName:       user.Spec.DisplayName,
			Description:       user.Spec.Description,
			Email:             user.Spec.Email,
			State:             string(user.Status.State),
			CreationTimestamp: user.CreationTimestamp.Unix(),
			Roles:             roles,
			Avatar:            "",
		}
		// terminus name
		if terminusName, ok := user.Annotations[constants.UserAnnotationTerminusNameKey]; ok {
			u.TerminusName = terminusName
		}

		if avatar, ok := user.Annotations[constants.UserAvatar]; ok {
			u.Avatar = avatar
		}

		if memoryLimit, ok := user.Annotations[constants.UserAnnotationLimitsMemoryKey]; ok {
			u.MemoryLimit = memoryLimit
		}
		if cpuLimit, ok := user.Annotations[constants.UserAnnotationLimitsCpuKey]; ok {
			u.CpuLimit = cpuLimit
		}

		if user.Status.LastLoginTime != nil {
			u.LastLoginTime = pointer.Int64(user.Status.LastLoginTime.Unix())
		}

		if s, err := settings.GetEnableHTTPSTaskState(user.Name); err != nil {
			log.Errorf("user '%s' get https task state err: %v", user.Name, err)
		} else {
			if s.State == settings.Succeeded {
				u.WizardComplete = true
			}
		}

		usersInfo = append(usersInfo, u)
	}

	if err != nil {
		response.HandleError(resp, errors.Errorf("list users: %v", err))
		return
	}

	response.Success(resp, api.NewListResult(usersInfo))
}

func (h *Handler) handleCreateUser(req *restful.Request, resp *restful.Response) {
	if !h.tryUserCreating(resp) {
		return
	}
	isSatisfied, err := h.checkClusterPodCapacity(req)
	if err != nil {
		response.HandleError(resp, errors.Errorf("user create: %v", err))
		return
	}
	if !isSatisfied {
		response.HandleBadRequest(resp, errors.Errorf("Unable to create user: Insufficient pods can allocate in the cluster."))
		return
	}
	var userCreate UserCreate
	err = req.ReadEntity(&userCreate)
	if err != nil {
		response.HandleBadRequest(resp, errors.Errorf("user create: %v", err))
		return
	}
	token := req.HeaderParameter(constants.AuthorizationTokenKey)

	if IsAppInstallationRunning(token) {
		response.HandleBadRequest(resp, errors.New("user create: please wait app installation to completed"))
		return
	}
	log.Info("userparams: ", userCreate)

	if userCreate.MemoryLimit == "" {
		response.HandleBadRequest(resp, errors.New("user create: memory_limit can not be empty"))
		return
	}
	if userCreate.CpuLimit == "" {
		response.HandleBadRequest(resp, errors.New("user create: cpu_limit can not be empty"))
		return
	}

	username := strings.ToLower(userCreate.Name)

	if username == "" || userCreate.Password == "" {
		response.HandleBadRequest(resp, errors.New("user create: no username or password provided"))
		return
	}

	var terminusName constants.TerminusName
	if strings.Contains(username, "@") {
		// username is terminusname
		terminusName = constants.TerminusName(username)
		username = terminusName.UserName()
	} else {
		op, err := operator.NewUserOperator()
		if err != nil {
			response.HandleBadRequest(resp, errors.Errorf("user create: %v", err))
			return
		}

		domainName, err := op.GetDomain()
		if err != nil {
			response.HandleBadRequest(resp, errors.Errorf("user create: %v", err))
			return
		}

		terminusName = constants.NewTerminusName(username, domainName)
	}

	if utils.ListContains(constants.SystemReservedKeyWords, username) {
		response.HandleBadRequest(resp, errors.Errorf("user create: %q is a system reserved keyword and cannot be set as a username.", userCreate.Name))
		return
	}

	if !utils.ListContains(defaultGlobalRoles, userCreate.OwnerRole) {
		response.HandleBadRequest(resp, errors.New("user create: invalid role binding"))
		return
	}
	memory, err := resource.ParseQuantity(userCreate.MemoryLimit)
	if err != nil {
		response.HandleBadRequest(resp, errors.New("user create: invalid format of memory limit"))
		return
	}

	cpu, err := resource.ParseQuantity(userCreate.CpuLimit)
	if err != nil {
		response.HandleBadRequest(resp, errors.New("user create: invalid format of cpu limit"))
		return
	}

	memoryLimit := memory.AsApproximateFloat64()
	cpuLimit := cpu.AsApproximateFloat64()
	defaultMemoryLimit, _ := resource.ParseQuantity(os.Getenv("USER_DEFAULT_MEMORY_LIMIT"))
	defaultCpuLimit, _ := resource.ParseQuantity(os.Getenv("USER_DEFAULT_CPU_LIMIT"))

	// user's memory limit must greater than default memory limit
	if defaultMemoryLimit.CmpInt64(int64(memoryLimit)) > 0 {
		response.HandleBadRequest(resp, errors.Errorf("user create: memory limit can not less than %s",
			defaultMemoryLimit.String()))
		return
	}
	// user's cpu limit must greater than default cpu limit
	if defaultCpuLimit.CmpInt64(int64(cpuLimit)) > 0 {
		response.HandleBadRequest(resp, errors.Errorf("user create: cpu limit can not less than %s core",
			defaultCpuLimit.String()))
		return
	}

	// get cluster level resource metrics
	metrics, err := utils.GetCurrentResource(token)
	if err != nil {
		response.HandleBadRequest(resp, errors.Errorf("user create: get cluster resource error: %s", err.Error()))
		return
	}
	// cluster's free memory size must greater than user's memory-limit size
	if memory.CmpInt64(int64(metrics.Memory.Total-metrics.Memory.Usage)) >= 0 {
		response.HandleBadRequest(resp, errors.Errorf("Unable to create user: Insufficient memory available in the cluster to meet the quota, required is: %.0f bytes, but available is: %.0f bytes", memoryLimit, metrics.Memory.Total-metrics.Memory.Usage))
		return
	}
	// cluster's free cpu core  must greater than user's cpu-limit core
	if (metrics.CPU.Total-metrics.CPU.Usage)-cpu.AsApproximateFloat64() < 0 {
		response.HandleBadRequest(resp, errors.Errorf("Unable to create user: Insufficient cpu available in the cluster to meet the quota, required is: %.1f, but available is: %.1f", cpuLimit, metrics.CPU.Total-metrics.CPU.Usage))
		return
	}

	h.userCreatingCount.Add(1)
	ctx := req.Request.Context()

	u := templates.UserCreateOption{
		Name:         username,
		OwnerRole:    userCreate.OwnerRole,
		DisplayName:  userCreate.DisplayName,
		Email:        string(terminusName),
		Password:     userCreate.Password,
		Description:  userCreate.Description,
		TerminusName: string(terminusName),
		MemoryLimit:  userCreate.MemoryLimit,
		CpuLimit:     userCreate.CpuLimit,
	}

	iamClient := h.newIamClient(req)

	userName, user, globalRoleBindingName, roleBinding := templates.NewUserAndGlobalRoleBinding(&u)
	_, err = iamClient.Users().Create(ctx, user, metav1.CreateOptions{})
	if err != nil {
		h.userCreatingCount.Add(-1)
		response.HandleError(resp, errors.Errorf("user create: %v", err))
		return
	}

	// add role binding
	_, err = iamClient.GlobalRoleBindings().Create(ctx, roleBinding, metav1.CreateOptions{})
	if err != nil {
		// rollback the user create
		iamClient.Users().Delete(ctx, userName, metav1.DeleteOptions{})
		h.userCreatingCount.Add(-1)

		response.HandleError(resp, errors.Errorf("user create: create globalrolebinding, %v", err))
		return
	}

	// Add workspace role binding, default is system-workspace-admin:system-workspace
	//workspaceRoleBindingName, workspaceRoleBinding := templates.NewWorkspaceRoleBinding(&u, defaultSystemWorkspace, defaultSystemWorkspaceRole)
	//_, err = iamClient.WorkspaceRoleBindings().Create(ctx, workspaceRoleBinding, metav1.CreateOptions{})
	//if err != nil {
	//	// rollback the user create
	//	iamClient.GlobalRoleBindings().Delete(ctx, globalRoleBindingName, metav1.DeleteOptions{})
	//	iamClient.Users().Delete(ctx, userName, metav1.DeleteOptions{})
	//	h.userCreatingCount.Add(-1)
	//
	//	response.HandleError(resp, errors.Errorf("user create: create workspacerolebinding, %v", err))
	//	return
	//}

	//kubeClient := runtime.NewKubeClient(req).Kubernetes()
	kubeClient := v1alpha1client.KubeClient.Kubernetes()

	clearUser := func(ctx context.Context) {
		//iamClient.WorkspaceRoleBindings().Delete(ctx, workspaceRoleBindingName, metav1.DeleteOptions{})
		iamClient.GlobalRoleBindings().Delete(ctx, globalRoleBindingName, metav1.DeleteOptions{})
		iamClient.Users().Delete(ctx, userName, metav1.DeleteOptions{})
		h.userCreatingCount.Add(-1)
	}

	// create userspace
	nsName, ns := templates.NewUserspace(u.Name)
	_, err = kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		clearUser(ctx)
		response.HandleError(resp, errors.Errorf("user create: create userspace %q, %v", ns.Name, err))
		return
	}
	userspaceRoleBinding := templates.NewUserspaceRoleBinding(u.Name, nsName, defaultUserspaceRole)
	_, err = kubeClient.RbacV1().RoleBindings(nsName).Create(ctx, userspaceRoleBinding, metav1.CreateOptions{})
	if err != nil {
		clearUser(ctx)
		kubeClient.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{})
		response.HandleError(resp, errors.Errorf("user create: create userspace %q rolebinding, %v", ns.Name, err))
		return
	}

	// copy ssl configmap to new userspace
	var applyCm *applyCorev1.ConfigMapApplyConfiguration
	sslConfig, err := kubeClient.CoreV1().ConfigMaps(constants.Namespace).Get(ctx, constants.NameSSLConfigMapName, metav1.GetOptions{})
	if err == nil && sslConfig != nil {
		sslConfig.Data["ephemeral"] = "true"

		applyCm = templates.NewApplyConfigmap(nsName, sslConfig.Data)
		_, err = kubeClient.CoreV1().ConfigMaps(nsName).Apply(ctx, applyCm, metav1.ApplyOptions{
			FieldManager: constants.ApplyPatchFieldManager})
		if err != nil {
			clearUser(ctx)
			response.HandleError(resp, errors.Errorf("user create: copy ssl configmap to userspace %q, %v", nsName, err))
			return
		}
	}

	// create user's sys apps
	appServiceClient := app_service.NewAppServiceClient()
	_, err = appServiceClient.InstallUserApps(u.Name, token)

	revokeCreates := func(ctx context.Context) {
		clearUser(ctx)
		if applyCm != nil {
			kubeClient.CoreV1().ConfigMaps(nsName).Delete(ctx, *applyCm.Name, metav1.DeleteOptions{})
		}
		kubeClient.RbacV1().RoleBindings(nsName).Delete(ctx, userspaceRoleBinding.Name, metav1.DeleteOptions{})
		kubeClient.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{})
		response.HandleError(resp, errors.Errorf("user create: install user's sys apps, %v", err))
	}
	if err != nil {
		// revoke creates
		revokeCreates(ctx)
		return
	}

	// check create status , revoke if fail
	createUserTask := &CommonTask{
		execFunc: func() {
			ticker := time.NewTicker(1 * time.Second)
			timeout := time.NewTimer(10 * time.Minute)
			taskCtx := context.Background()

			defer func() {
				ticker.Stop()
				timeout.Stop()
			}()

			for {
				select {
				case <-ticker.C:
					// get delete user's sys app status
					res, err := appServiceClient.UserAppsStatus(username, token)
					if err != nil {
						log.Errorf("create user: get user(%s)'s sys apps creating, %v", username, err)
						h.userCreatingCount.Add(-1)
						return
					}

					resData := res["data"].(map[string]interface{})
					status := resData["status"].(string)
					if status == "Creating" {
						continue
					}

					if status == "Failed" {
						errStr := resData["error"].(string)
						log.Errorf("create user: %q, error: %s", username, errStr)
						revokeCreates(taskCtx)
						return
					}

					if status == "Created" {
						log.Infof("create user: %q success", username)
						h.userCreatingCount.Add(-1)
						return
					}

				case <-timeout.C:
					log.Errorf("create user: %q timeout", username)
					h.userCreatingCount.Add(-1)
					return
				} // end select
			} // end for

		}, // end func define
	}

	task.LocalTaskQueue.Push("create-user-"+username, createUserTask)

	response.SuccessNoData(resp)
}

func (h *Handler) handleDescribeUser(req *restful.Request, resp *restful.Response) {
	name := req.PathParameter("user")
	ctx, iamClient := req.Request.Context(), h.newIamClient(req)

	user, err := iamClient.Users().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			response.HandleNotFound(resp, errors.Errorf("describe user: %v", err))
			return
		}
		response.HandleError(resp, errors.Errorf("describe user: %v", err))
		return
	}

	ownerRoles, err := h.getRolesByUserName(name, ctx, iamClient)
	if err != nil {
		response.HandleError(resp, errors.Errorf("describe user: list global rolebindings, %v", err))
		return
	}

	u := UserInfo{
		UID:               string(user.UID),
		Name:              user.Name,
		DisplayName:       user.Spec.DisplayName,
		Description:       user.Spec.Description,
		Email:             user.Spec.Email,
		State:             string(user.Status.State),
		CreationTimestamp: user.CreationTimestamp.Unix(),
	}

	// terminus name
	if terminusName, ok := user.Annotations[constants.UserAnnotationTerminusNameKey]; ok {
		u.TerminusName = terminusName
	}

	if memoryLimit, ok := user.Annotations[constants.UserAnnotationLimitsMemoryKey]; ok {
		u.MemoryLimit = memoryLimit
	}
	if cpuLimit, ok := user.Annotations[constants.UserAnnotationLimitsCpuKey]; ok {
		u.CpuLimit = cpuLimit
	}

	if user.Status.LastLoginTime != nil {
		u.LastLoginTime = pointer.Int64(user.Status.LastLoginTime.Unix())
	}
	u.Roles = ownerRoles

	if s, err := settings.GetEnableHTTPSTaskState(user.Name); err != nil {
		log.Errorf("user %q, get https state, %v", user.Name, err)
	} else {
		if s.State == settings.Succeeded {
			u.WizardComplete = true
		}
	}

	response.Success(resp, u)
}

func (h *Handler) handleListUserLoginRecords(req *restful.Request, resp *restful.Response) {
	name := req.PathParameter("user")
	ctx, iamClient := req.Request.Context(), h.newIamClient(req)

	users, err := h.listUsers(ctx, iamClient)
	if err != nil {
		response.HandleError(resp, errors.Errorf("list user login records: %v", err))
		return
	}

	userIsExists := func() bool {
		for _, user := range users {
			if user.Name == name {
				return true
			}
		}
		return false
	}
	if !userIsExists() {
		response.HandleError(resp, errors.Errorf("list user login records: user %q not exists", name))
		return
	}
	lldapClient, err := lldap.New()
	if err != nil {
		log.Errorf("make lldap client err=%v", err)
		return
	}
	loginRecords, err := lldapClient.Users().LoginRecords(req.Request.Context(), name)
	if err != nil {
		response.HandleError(resp, errors.Errorf("list user login records: %v", err))
		return
	}
	//loginRecords, err := iamClient.LoginRecords().List(ctx, metav1.ListOptions{})
	//if err != nil {
	//	response.HandleError(resp, errors.Errorf("list user login records: %v", err))
	//	return
	//}

	records := make([]LoginRecord, 0)
	for _, r := range loginRecords {
		records = append(records, LoginRecord{
			Type:      "Token",
			Success:   r.Success,
			UserAgent: r.UserAgent,
			Reason:    r.Reason,
			SourceIP:  r.SourceIp,
			LoginTime: func() *int64 {
				t := r.CreationDate.Unix()
				return &t
			}(),
		})
	}
	//klog.Infof("loginRecord: %v", records[0])

	//for _, r := range loginRecords.Items {
	//	if strings.HasPrefix(r.Name, name) {
	//		records = append(records, LoginRecord{
	//			Success:   r.Spec.Success,
	//			Type:      string(r.Spec.Type),
	//			UserAgent: r.Spec.UserAgent,
	//			Reason:    r.Spec.Reason,
	//			LoginTime: pointer.Int64(r.CreationTimestamp.Unix()),
	//		})
	//	}
	//}
	response.Success(resp, api.NewListResult(records))
}

func (h *Handler) handleListUserRoles(_ *restful.Request, resp *restful.Response) {
	response.Success(resp, api.NewListResult(defaultGlobalRoles))
}

func (h *Handler) handleResetUserPassword(req *restful.Request, resp *restful.Response) {
	var passwordReset PasswordReset
	if err := req.ReadEntity(&passwordReset); err != nil {
		response.HandleBadRequest(resp, errors.Errorf("reset password: %v", err))
		return
	}

	log.Info("reset user password")

	ctx, iamClient := req.Request.Context(), h.newIamClient(req)

	userName := req.PathParameter("user")
	user, err := iamClient.Users().Get(ctx, userName, metav1.GetOptions{})
	if err != nil {
		response.HandleError(resp, errors.Errorf("reset password: get user err, %v", err))
		return
	}

	lldapClient, err := lldap.New()
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	if userName == constants.Username {
		// change user password itself
		if passwordReset.Password == "" {
			response.HandleError(resp, errors.New("reset password: new password is empty"))
			return
		}

		if len(passwordReset.CurrentPassword) > 0 {
			// Password field is mean new password
			_, err = auth.Login("http://lldap-service.os-framework:17170", userName, passwordReset.CurrentPassword)
			if err != nil {
				response.HandleError(resp, errors.Errorf("reset password: verify password hash err, %v", err))
				return
			}

			if passwordReset.Password == passwordReset.CurrentPassword {
				response.HandleBadRequest(resp, errors.New("reset password: the tow passwords must be different"))
				return
			}

		} else {
			tokenStr := req.HeaderParameter(constants.AuthorizationTokenKey)
			if tokenStr == "" {
				response.HandleUnauthorized(resp, response.NewTokenValidationError("token not provided"))
				return
			}

			claims, err := apiRuntime.ParseToken(tokenStr)
			if err != nil {
				response.HandleUnauthorized(resp, response.NewTokenValidationError("parse token", err))
				return
			}

			if claims.Username != constants.Username {
				response.HandleError(resp, errors.Errorf("reset password: verify token err, invalid token"))
				return
			}

		}

		// Reset Password
		//user.Spec.EncryptedPassword = passwordReset.Password
		if user.Annotations[constants.UserTerminusWizardStatus] != string(constants.Completed) {
			// only initializing in progress
			user.Annotations[constants.UserTerminusWizardStatus] = string(constants.Completed)

			// init completed, user's wizard will be closed
			go func() {
				kubeClient := runtime.NewKubeClient(req)
				deploy := kubeClient.Kubernetes().AppsV1().Deployments(constants.Namespace)
				ctx := context.Background()
				wizard, err := deploy.Get(ctx, "wizard", metav1.GetOptions{})
				if err != nil {
					klog.Error("find wizard deployment error, ", err)
					return
				}

				err = deploy.Delete(ctx, wizard.Name, metav1.DeleteOptions{})
				if err != nil && !apierrors.IsNotFound(err) {
					klog.Error("delete deployment wizard error, ", err)
					return
				}

				klog.Info("success to delete wizard")
			}()

		}

		err = lldapClient.Users().ResetPassword(ctx, userName, passwordReset.Password)
		if err != nil {
			response.HandleError(resp, errors.Errorf("reset password: set user password err, %v", err))
			return
		}
		_, err = iamClient.Users().Update(ctx, user, metav1.UpdateOptions{})
		if err != nil {
			response.HandleError(resp, errors.Errorf("reset password: update user err, %v", err))
			return
		}

	} else {
		admin, err := iamClient.Users().Get(ctx, constants.Username, metav1.GetOptions{})
		if err != nil {
			response.HandleError(resp, errors.Errorf("reset password: get user role err, %v", err))
			return
		}

		role, ok := admin.Annotations[constants.UserAnnotationOwnerRole]
		if !ok {
			response.HandleError(resp, errors.Errorf("invalid user %q, no owner role annotation", admin.Name))
			return
		}

		if role != constants.RolePlatformAdmin {
			response.HandleError(resp, errors.New("no privilege to reset password of another user"))
			return
		}

		//user.Spec.EncryptedPassword = passwordReset.Password
		err = lldapClient.Users().ResetPassword(ctx, userName, passwordReset.Password)
		if err != nil {
			response.HandleError(resp, errors.Errorf("reset password: set user password err, %v", err))
			return
		}
		_, err = iamClient.Users().Update(ctx, user, metav1.UpdateOptions{})
		if err != nil {
			response.HandleError(resp, errors.Errorf("reset password: update user err, %v", err))
			return
		}

	}

	response.SuccessNoData(resp)
}

func (h *Handler) handleUpdateUserLimits(req *restful.Request, resp *restful.Response) {
	var userResourceLimits UserResourceLimit
	if err := req.ReadEntity(&userResourceLimits); err != nil {
		response.HandleBadRequest(resp, errors.Errorf("update user's resource limit: %v", err))
		return
	}

	memory, err := resource.ParseQuantity(userResourceLimits.MemoryLimit)
	if err != nil {
		response.HandleBadRequest(resp, errors.New("user create: invalid format of memory limit"))
		return
	}

	cpu, err := resource.ParseQuantity(userResourceLimits.CpuLimit)
	if err != nil {
		response.HandleBadRequest(resp, errors.New("user create: invalid format of cpu limit"))
		return
	}

	defaultMemoryLimit, _ := resource.ParseQuantity(os.Getenv("USER_DEFAULT_MEMORY_LIMIT"))
	defaultCpuLimit, _ := resource.ParseQuantity(os.Getenv("USER_DEFAULT_CPU_LIMIT"))

	if defaultMemoryLimit.CmpInt64(int64(memory.AsApproximateFloat64())) > 0 {
		response.HandleBadRequest(resp, errors.Errorf("user create: memory limit can not less than %s",
			defaultMemoryLimit.String()))
		return
	}

	if defaultCpuLimit.CmpInt64(int64(cpu.AsApproximateFloat64())) > 0 {
		response.HandleBadRequest(resp, errors.Errorf("user create: cpu limit can not less than %s core",
			defaultCpuLimit.String()))
		return
	}

	ctx, iamClient := req.Request.Context(), h.newIamClient(req)
	username := req.PathParameter("user")
	user, err := iamClient.Users().Get(ctx, username, metav1.GetOptions{})
	if err != nil {
		response.HandleError(resp, errors.Errorf("get user err: %v", err))
		return
	}

	user.Annotations[constants.UserAnnotationLimitsMemoryKey] = userResourceLimits.MemoryLimit
	user.Annotations[constants.UserAnnotationLimitsCpuKey] = userResourceLimits.CpuLimit
	_, err = iamClient.Users().Update(ctx, user, metav1.UpdateOptions{})
	if err != nil {
		response.HandleError(resp, errors.Errorf("update user err: %v", err))
		return
	}
	response.SuccessNoData(resp)
}

func (h *Handler) handleDeleteUser(req *restful.Request, resp *restful.Response) {
	name := req.PathParameter("user")
	iamClient := h.newIamClient(req)

	// delete user's sys app
	token := req.HeaderParameter(constants.AuthorizationTokenKey)
	appServiceClient := app_service.NewAppServiceClient()
	_, err := appServiceClient.UninstallUserApps(name, token)
	if err != nil {
		response.HandleError(resp, errors.Errorf("user delete: uninstall user's sys apps error, %v", err))
		return
	}

	// delete user info after user's sys apps deleted
	// TODO: send the error msg of delete user to client
	deleteUserTask := &CommonTask{
		execFunc: func() {
			ticker := time.NewTicker(1 * time.Second)
			timeout := time.NewTimer(10 * time.Minute)
			taskCtx := context.Background()

			defer func() {
				ticker.Stop()
				timeout.Stop()
			}()

			for {
				select {
				case <-ticker.C:
					// get delete user's sys app status
					res, err := appServiceClient.UserAppsStatus(name, token)
					if err != nil {
						log.Errorf("delete user: get user(%s)'s sys apps deleting error %v", name, err)
						return
					}

					resData := res["data"].(map[string]interface{})
					status := resData["status"].(string)
					if status != "Deleted" {
						// bug fix
						errorStr := resData["error"].(string)
						if status != "Failed" && !strings.Contains(errorStr, "release: not found") {
							continue
						}
					}

					// delete user's globalrolebinding
					err = iamClient.GlobalRoleBindings().Delete(taskCtx, name, metav1.DeleteOptions{})
					if err != nil {
						log.Warnf("delete user: delete %q user globalrolebinding err, %v", name, err)
					}

					// delete user's workspacerolebinding
					//err = iamClient.WorkspaceRoleBindings().Delete(taskCtx, name, metav1.DeleteOptions{})
					//if err != nil {
					//	log.Warnf("delete user: delete %q user workspacerolebinding err, %v", name, err)
					//}

					ksClient := v1alpha1client.KubeClient.Kubernetes()

					ns, _ := templates.NewUserspace(name)
					userspaceRoleBinding := templates.NewUserspaceRoleBinding(name, ns, defaultUserspaceRole)
					err = ksClient.RbacV1().RoleBindings(ns).Delete(taskCtx, userspaceRoleBinding.Name, metav1.DeleteOptions{})
					if err != nil {
						log.Warnf("delete userspace rolebinding err, %v", err)
					}

					err = ksClient.CoreV1().Namespaces().Delete(taskCtx, ns, metav1.DeleteOptions{})
					if err != nil {
						log.Warnf("delete userspace %q err, %v", ns, err)
					}

					err = iamClient.Users().Delete(taskCtx, name, metav1.DeleteOptions{})
					if err != nil {
						log.Warnf("delete user %q err, %v", name, err)
					}

					return

				case <-timeout.C:
					log.Errorf("delete user: %q timeout", name)
					return
				} // end select
			} // end for

		}, // end func define
	}

	task.LocalTaskQueue.Push("delete-user-"+name, deleteUserTask)

	response.SuccessNoData(resp)
}

func (h *Handler) handleUserStatus(req *restful.Request, resp *restful.Response) {
	name := req.PathParameter("user")

	token := req.HeaderParameter(constants.AuthorizationTokenKey)
	appServiceClient := app_service.NewAppServiceClient()

	res, err := appServiceClient.UserAppsStatus(name, token)
	if err != nil {
		response.HandleError(resp, errors.Errorf("user status: get user status err, %v", err))
		return
	}

	resData := res["data"].(map[string]interface{})
	status := resData["status"].(string)
	if status == "Failed" {
		errStr := resData["error"].(string)
		response.HandleError(resp, errors.Errorf("user status: user action err, %v", errStr))
		return
	}

	ports := resData["ports"].(map[string]interface{})

	var address UserAddress

	if status == "Created" {
		// if the user admin does not apply a frps
		host := req.Request.Host
		if host != "" {
			host = strings.Split(host, ":")[0]
		}

		if govalidator.IsIP(host) {
			address = UserAddress{
				Desktop: fmt.Sprintf("%s:%d", host, int(ports["desktop"].(float64))),
				Wizard:  fmt.Sprintf("%s:%d", host, int(ports["wizard"].(float64))),
			}
		} else {
			userOp, err := operator.NewUserOperator()
			if err != nil {
				response.HandleError(resp, errors.Errorf("user status: new user operator, %v", err))
				return
			}

			user, err := userOp.GetUser(name)
			if err != nil {
				response.HandleError(resp, errors.Errorf("user status: get user %q, %v", name, err))
				return
			}

			isEphemeral, zone, err := userOp.GetUserDomainType(user)
			if err != nil {
				response.HandleError(resp, errors.Errorf("user status: get user domain type: %v", err))
				return
			}

			if isEphemeral {
				// new user
				address = UserAddress{
					Wizard: fmt.Sprintf("wizard-%s.%s", name, zone),
				}
			} else {
				// impossible
				log.Warnw("imposible result", "zone", zone, "name", name)
				address = UserAddress{
					Wizard: zone,
				}
			}
		}

	}

	userStatus := &UserStatusResponse{
		Name:    name,
		Status:  status,
		Address: address,
	}

	response.Success(resp, userStatus)
}

func RequestToken(token string, data map[string]string) (*TokenResponse, int, error) {
	c := httpclient.New(&httpclient.Option{
		Debug:   true,
		Timeout: 30 * time.Second},
	)

	if token != "" {
		c.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	c.SetFormData(data)

	_url := fmt.Sprintf("%s://%s%s", constants.KubeSphereAPIScheme, constants.KubeSphereAPIHost, kubeSphereAPIToken)
	respToken, err := c.R().Post(_url)
	if err != nil {
		return nil, -1, err
	}

	respBytes := respToken.Body()

	log.Debugw("request token", "requestUrl", _url,
		"requestHeader", c.Header,
		"requestData", data,
		"responseCode", respToken.StatusCode(),
		"responseBody", string(respBytes))

	if respToken.StatusCode() != http.StatusOK {
		var e KubesphereError
		if err := json.Unmarshal(respBytes, &e); err == nil && e.Error != "" {
			return nil, respToken.StatusCode(), errors.Errorf("%s, %s", e.Error, e.ErrorDescription)
		}
		return nil, respToken.StatusCode(), errors.Errorf("request kubesphere api err: %v", http.StatusText(respToken.StatusCode()))
	}

	var t TokenResponse
	if err = json.Unmarshal(respBytes, &t); err == nil {
		if t.AccessToken == "" {
			return nil, -1, errors.New("got empty access token")
		}

		claims, err := runtime.ParseToken(t.AccessToken)
		if err != nil {
			return nil, -1, errors.Errorf("parse access token err: %v", err)
		}
		t.ExpiresAt = claims.ExpiresAt
		return &t, 200, nil
	}
	return nil, -1, err
}

func (h *Handler) isUserCreating() bool {
	return h.userCreatingCount.Load() > 0
}

func (h *Handler) lockUserCreating() {
	h.userCreatingCount.Store(-1)
}

func (h *Handler) unlockUserCreating() {
	h.userCreatingCount.Store(0)
}

func (h *Handler) tryUserCreating(resp *restful.Response) bool {
	if h.userCreatingCount.Load() >= 0 {
		return true
	} else {
		response.HandleForbidden(resp, errors.New("user create: forbidden by system"))
		return false
	}
}

func (h *Handler) handleGetUserMetrics(req *restful.Request, resp *restful.Response) {
	user := req.PathParameter("user")
	token := req.HeaderParameter(constants.AuthorizationTokenKey)
	appServiceClient := app_service.NewAppServiceClient()

	r, err := appServiceClient.GetUserMetrics(user, token)
	if err != nil {
		response.HandleError(resp, err)
	}
	resp.WriteAsJson(r)
}

func IsAppInstallationRunning(token string) bool {
	appServiceClient := app_service.NewAppServiceClient()
	running, err := appServiceClient.GetInstallationRunningList(token)
	if err != nil {
		return true
	}

	return len(running) > 0
}

func (h *Handler) handleValidateUserPassword(req *restful.Request, resp *restful.Response) {
	var userPassword UserPassword
	if err := req.ReadEntity(&userPassword); err != nil {
		response.HandleBadRequest(resp, errors.Errorf("validate password: %v", err))
		return
	}

	if userPassword.Password == "" {
		response.HandleError(resp, errors.New("validate password: new password is empty"))
		return
	}

	_, err := auth.Login("http://lldap-service.os-framework:17170", userPassword.UserName, userPassword.Password)
	if err != nil {
		response.HandleError(resp, errors.Errorf("validate password: verify password hash err, %v", err))
		return
	}

	response.SuccessNoData(resp)
}

func (h *Handler) checkClusterPodCapacity(req *restful.Request) (bool, error) {
	kClient := runtime.NewKubeClient(req)
	nodes, err := kClient.Kubernetes().CoreV1().Nodes().List(req.Request.Context(), metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	var currentPodNum, maxPodNum int64
	nodeMap := sets.String{}
	for _, node := range nodes.Items {
		if !IsNodeReady(&node) || node.Spec.Unschedulable {
			continue
		}
		pods, _ := node.Status.Capacity.Pods().AsInt64()
		maxPodNum += pods
		nodeMap.Insert(node.Name)
	}

	pods, err := kClient.Kubernetes().CoreV1().Pods(corev1.NamespaceAll).List(req.Request.Context(), metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	for _, pod := range pods.Items {
		if IsPodActive(&pod) && (nodeMap.Has(pod.Spec.NodeName) || pod.Status.Phase == corev1.PodPending) {
			currentPodNum++
		}
	}
	klog.Infof("currentPodNum :%v", currentPodNum)
	if currentPodNum+minPodNumPerUser > maxPodNum-reservedPodNumForUser {
		return false, nil
	}
	return true, nil
}

func IsPodActive(p *corev1.Pod) bool {
	return corev1.PodSucceeded != p.Status.Phase &&
		corev1.PodFailed != p.Status.Phase &&
		p.DeletionTimestamp == nil
}

func IsNodeReady(node *corev1.Node) bool {
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
