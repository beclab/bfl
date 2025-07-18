package v1alpha1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"bytetrade.io/web3os/bfl/internal/log"
	"bytetrade.io/web3os/bfl/pkg/api"
	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/app_service/v1"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/event/v1"
	"bytetrade.io/web3os/bfl/pkg/lldap"
	"bytetrade.io/web3os/bfl/pkg/task"
	"bytetrade.io/web3os/bfl/pkg/task/settings"
	"bytetrade.io/web3os/bfl/pkg/utils"
	"bytetrade.io/web3os/bfl/pkg/utils/httpclient"
	"github.com/beclab/lldap-client/pkg/auth"

	"github.com/emicklei/go-restful/v3"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
	"go.uber.org/atomic"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
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
	constants.RoleOwner,
	// "platform-regular",    useless role
	// "users-manager",
	constants.RoleAdmin,
	constants.RoleOwner,
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

	newToken, err := auth.Refresh("http://lldap-service.os-platform:17170", pt.Token)
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
	token := req.HeaderParameter(constants.AuthorizationTokenKey)

	if passwordReset.Password == "" {
		response.HandleError(resp, errors.New("reset password: new password is empty"))
		return
	}

	if passwordReset.Password == passwordReset.CurrentPassword {
		response.HandleBadRequest(resp, errors.New("reset password: the tow passwords must be different"))
		return
	}

	log.Info("start reset user password")

	ctx, iamClient := req.Request.Context(), h.newIamClient(req)

	userName := req.PathParameter("user")
	user, err := iamClient.Users().Get(ctx, userName, metav1.GetOptions{})
	if err != nil {
		response.HandleError(resp, errors.Errorf("reset password: get user err, %v", err))
		return
	}

	//lldapClient, err := lldap.New()
	//if err != nil {
	//	response.HandleError(resp, err)
	//	return
	//}

	//if userName == constants.Username {
	// change user password itself

	//if len(passwordReset.CurrentPassword) > 0 {
	//	// Password field is mean new password
	//	_, err = auth.Login("http://lldap-service.os-platform:17170", userName, passwordReset.CurrentPassword)
	//	if err != nil {
	//		response.HandleError(resp, errors.Errorf("reset password: verify password hash err, %v", err))
	//		return
	//	}
	//
	//} else {
	//	tokenStr := req.HeaderParameter(constants.AuthorizationTokenKey)
	//	if tokenStr == "" {
	//		response.HandleUnauthorized(resp, response.NewTokenValidationError("token not provided"))
	//		return
	//	}
	//
	//	claims, err := apiRuntime.ParseToken(tokenStr)
	//	if err != nil {
	//		response.HandleUnauthorized(resp, response.NewTokenValidationError("parse token", err))
	//		return
	//	}
	//
	//	if claims.Username != constants.Username {
	//		response.HandleError(resp, errors.Errorf("reset password: verify token err, invalid token"))
	//		return
	//	}
	//
	//}

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
		_, err = iamClient.Users().Update(ctx, user, metav1.UpdateOptions{})
		if err != nil {
			response.HandleError(resp, errors.Errorf("reset password: update user err, %v", err))
			return
		}

	}
	url := fmt.Sprintf("http://authelia-backend.os-framework:9091/api/reset/%s/password", userName)
	client := resty.New()
	res, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("X-Authorization", token).
		SetHeader("X-BFL-USER", userName).
		SetBody(&passwordReset).
		Post(url)
	if err != nil {
		response.HandleError(resp, errors.Errorf("reset password: request authelia failed %v", err))
		return
	}
	if res.StatusCode() != http.StatusOK {
		response.HandleError(resp, errors.New(res.String()))
		return
	}

	response.SuccessNoData(resp)
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

	_, err := auth.Login("http://lldap-service.os-platform:17170", userPassword.UserName, userPassword.Password)
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
