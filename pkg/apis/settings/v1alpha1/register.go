package v1alpha1

import (
	"net/http"

	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/apis"
	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/app_service/v1"
	"bytetrade.io/web3os/bfl/pkg/constants"

	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
)

const (
	ParamServiceName  = "service"
	ParamAppName      = "app"
	ParamEntranceName = "entrance_name"
	ParamDataType     = "dataType"
	ParamGroup        = "group"
	ParamVersion      = "version"
)

var ModuleVersion = runtime.ModuleVersion{Name: "settings", Version: "v1alpha1"}

var tags = []string{"settings"}

func AddContainer(c *restful.Container) error {
	ws := runtime.NewWebService(ModuleVersion)
	ws.Consumes(restful.MIME_JSON)
	ws.Produces(restful.MIME_JSON)

	handler := New()

	ws.Route(ws.POST("/binding-zone").
		To(handler.handleBindingUserZone).
		Doc("Binding user zone.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Reads(PostTerminusName{}).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	// FIXME: only for testing, noqa
	ws.Route(ws.GET("/unbind-zone").
		To(handler.handleUnbindingUserZone).
		Doc("Unbinding user zone.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.POST("/ssl/enable").
		To(handler.handleEnableHTTPs).
		Doc("Enable https.").
		Param(ws.BodyParameter("body", "ip").Required(false).DataType("json")).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.POST("/reverse-proxy").
		To(handler.handleChangeReverseProxyConfig).
		Doc("Change the current reverse proxy settings.").
		Reads(ReverseProxyConfig{}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.GET("/reverse-proxy").
		To(handler.handleGetReverseProxyConfig).
		Doc("Get the current reverse proxy settings.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.GET("/default-reverse-proxy").
		To(handler.handleGetDefaultReverseProxyConfig).
		Doc("Get the default reverse proxy config, which will be applied at user activation, if reverse proxy is enabled.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.GET("/ssl/task-state").
		To(handler.handleGetEnableHTTPSTaskState).
		Doc("Get enable https task state.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.GET("/launcher-acc-policy").
		To(handler.handleGetLauncherAccessPolicy).
		Doc("Get launcher access policy.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.POST("/launcher-acc-policy").
		To(handler.handleUpdateLauncherAccessPolicy).
		Doc("Get launcher access policy.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Reads(LauncherAccessPolicy{}).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.GET("/launcher-public-domain-access-policy").
		To(handler.handleGetPublicDomainAccessPolicy).
		Doc("Get public domain access policy.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Reads(PublicDomainAccessPolicy{}).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.POST("/launcher-public-domain-access-policy").
		To(handler.handleUpdatePublicDomainAccessPolicy).
		Doc("Update public domain access policy.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Reads(PublicDomainAccessPolicy{}).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.POST("/config-system").
		To(handler.handleUpdateLocale).
		Doc("Update user locale.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Reads(apis.PostLocale{}).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.GET("/config-system").
		To(handler.HandleGetSysConfig).
		Doc("get user locale.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.POST("/set-login-background").
		To(handler.handlerUpdateUserLoginBackground).
		Doc("Update user login background.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.POST("/set-avatar").
		To(handler.handlerUpdateUserAvatar).
		Doc("Update user avatar.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	// service api
	// *** OBSOLETE ***
	// ws.Route(ws.POST("/services/{"+ParamServiceName+"}/enable").
	// 	To(handler.handleEnableService).
	// 	Doc("Enable system service.").
	// 	Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
	// 	Param(ws.PathParameter(ParamServiceName, "service name").DataType("string").Required(true)).
	// 	Metadata(restfulspec.KeyOpenAPITags, tags).
	// 	Returns(http.StatusOK, "", response.Response{}))

	// ws.Route(ws.POST("/services/{"+ParamServiceName+"}/disable").
	// 	To(handler.handleDisableService).
	// 	Doc("Disable system service.").
	// 	Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
	// 	Param(ws.PathParameter(ParamServiceName, "service name").DataType("string").Required(true)).
	// 	Metadata(restfulspec.KeyOpenAPITags, tags).
	// 	Returns(http.StatusOK, "", response.Response{}))

	// ws.Route(ws.GET("/services").
	// 	To(handler.handleGetServicesStatus).
	// 	Doc("Get services status.").
	// 	Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
	// 	Metadata(restfulspec.KeyOpenAPITags, tags).
	// 	Returns(http.StatusOK, "", response.Response{}))

	// notification api

	ws.Route(ws.GET("/notification/config").
		To(handler.getNotificationConfig).
		Doc("Get user's notification configs.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.QueryParameter("type", "config or receiver type, known values include dingtalk, email, slack, webhook, wechat").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.POST("/notification/config").
		To(handler.applyNotificationConfig).
		Doc("Create or update user's notification config.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Reads(NotificationSetting{}).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.DELETE("/notification/config").
		To(handler.deleteNotificationConfig).
		Doc("Delete user's notification config.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.QueryParameter("type", "config or receiver type, known values include dingtalk, email, slack, webhook, wechat").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	ws.Route(ws.POST("/notification/config/verify").
		To(handler.verifyNotificationConfig).
		Doc("Verify user's notification config.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Reads(NotificationSetting{}).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{}))

	// app settings
	ws.Route(ws.POST("/applications/{"+ParamAppName+"}/setup/policy").
		To(handler.setupAppPolicy).
		Doc("Setup application access policy.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter(ParamAppName, "app name").DataType("string").Required(true)).
		Reads(app_service.ApplicationSettingsPolicy{}).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{Data: app_service.ApplicationsSettings{}}))

	ws.Route(ws.GET("/applications/{"+ParamAppName+"}/setup/policy").
		To(handler.getAppPolicy).
		Doc("Get application access policy.").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter(ParamAppName, "app name").DataType("string").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{Data: app_service.ApplicationsSettings{}}))

	ws.Route(ws.POST("/applications/{"+ParamAppName+"}/{"+ParamEntranceName+"}/setup/policy").
		To(handler.setupAppEntrancePolicy).
		Doc("Setup application entrance policy").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter(ParamAppName, "app name").DataType("string").Required(true)).
		Param(ws.PathParameter(ParamEntranceName, "entrance name").DataType("string").Required(true)).
		Reads(app_service.ApplicationSettingsDomain{}).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{Data: app_service.ApplicationsSettings{}}))

	// app set custom domain
	ws.Route(ws.POST("/applications/{"+ParamAppName+"}/{"+ParamEntranceName+"}/setup/domain").
		To(handler.setupAppCustomDomain).
		Doc("Setup application domain").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter(ParamAppName, "app name").DataType("string").Required(true)).
		Param(ws.PathParameter(ParamEntranceName, "entrance name").DataType("string").Required(true)).
		Reads(app_service.ApplicationSettingsDomain{}).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{Data: app_service.ApplicationsSettings{}}))

	ws.Route(ws.GET("/applications/{"+ParamAppName+"}/setup/domain").
		To(handler.getAppCustomDomain).
		Doc("Get application domain settings").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter(ParamAppName, "app name").DataType("string").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{Data: app_service.ApplicationsSettings{}}))

	ws.Route(ws.GET("/applications/{"+ParamAppName+"}/{"+ParamEntranceName+"}/setup/domain/finish").
		To(handler.finishAppCustomDomainCnameTarget).
		Doc("Finish application domain cname target setting").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter(ParamAppName, "app name").DataType("string").Required(true)).
		Param(ws.PathParameter(ParamEntranceName, "entrance name").DataType("string").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{Data: app_service.ApplicationsSettings{}}))

	ws.Route(ws.POST("/applications/{"+ParamAppName+"}/{"+ParamEntranceName+"}/setup/auth-level").
		To(handler.setupAppAuthorizationLevel).
		Doc("Setup application auth level").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter(ParamAppName, "app name").DataType("string").Required(true)).
		Param(ws.PathParameter(ParamEntranceName, "entrance name").DataType("string").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{Data: app_service.ApplicationsSettings{}}))

	ws.Route(ws.GET("/applications/{"+ParamAppName+"}/entrances").
		To(handler.getAppEntrances).
		Doc("Get application entrances").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter(ParamAppName, "app name").DataType("string").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", response.Response{Data: app_service.Entrances{}}))

	ws.Route(ws.GET("/apps/permissions").
		To(handler.applicationPermissionList).
		Doc("Get application permission list").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", nil))

	ws.Route(ws.GET("/apps/permissions/{"+ParamAppName+"}").
		To(handler.applicationPermission).
		Doc("Get application permission list").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter(ParamAppName, "app name").DataType("string").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", nil))

	ws.Route(ws.GET("/apps/provider-registry/{"+ParamAppName+"}").
		To(handler.getApplicationProviderList).
		Doc("Get application provider-registry list").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", nil))

	ws.Route(ws.GET("/apps/{"+ParamAppName+"}/subject").
		To(handler.getApplicationSubjectList).
		Doc("Get application subject list").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", nil))

	ws.Route(ws.GET("/apps/provider-registry/{"+ParamDataType+"}/{"+ParamGroup+"}/{"+ParamVersion+"}").
		To(handler.getProviderRegistry).
		Doc("Get an provider registry").
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter(ParamDataType, "dataType").DataType("string").Required(true)).
		Param(ws.PathParameter(ParamGroup, "group").DataType("string").Required(true)).
		Param(ws.PathParameter(ParamVersion, "version").DataType("string").Required(true)).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Returns(http.StatusOK, "", nil))

	// system upgrade
	ws.Route(ws.GET("/upgrade/newversion").
		To(handler.newVersion).
		Doc("get there is a new version can be upgrade or not").
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.QueryParameter("dev_mode", "dev mode").DataType("bool")).
		Returns(http.StatusOK, "Success to get the new version", &response.Response{}))

	ws.Route(ws.GET("/upgrade/state").
		To(handler.upgradeState).
		Doc("get the running upgrade state").
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Returns(http.StatusOK, "Success to get state", &response.Response{}))

	ws.Route(ws.POST("/upgrade").
		To(handler.upgrade).
		Doc("upgrade system").
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.QueryParameter("dev_mode", "dev mode").DataType("bool")).
		Returns(http.StatusOK, "Success to start upgrading", &response.Response{}))

	ws.Route(ws.POST("/upgrade/cancel").
		To(handler.upgradeCancel).
		Doc("cancel the running upgrading").
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Returns(http.StatusOK, "Success to cancel", &response.Response{}))

	// backup server apis

	ws.Route(ws.GET("/backup/available").
		To(handler.availableBackupServer).
		Doc("backup server available").
		Metadata(restfulspec.KeyOpenAPITags, []string{"backup"}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Returns(http.StatusOK, "", &response.Response{}))

	ws.Route(ws.POST("/backup/plans").
		To(handler.createBackupPlan).
		Doc("create backup plan").
		Metadata(restfulspec.KeyOpenAPITags, []string{"backup"}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Returns(http.StatusOK, "", &response.Response{}))

	ws.Route(ws.PUT("/backup/plans/{name}").
		To(handler.updateBackupPlan).
		Doc("update specific backup plan").
		Metadata(restfulspec.KeyOpenAPITags, []string{"backup"}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter("name", "backup plan name").DataType("string").Required(true)).
		Returns(http.StatusOK, "", &response.Response{}))

	ws.Route(ws.GET("/backup/plans").
		To(handler.listBackupPlans).
		Doc("list backup plans").
		Metadata(restfulspec.KeyOpenAPITags, []string{"backup"}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Returns(http.StatusOK, "", &response.Response{}))

	ws.Route(ws.GET("/backup/plans/{name}").
		To(handler.describeBackupPlan).
		Doc("get backup plan details").
		Metadata(restfulspec.KeyOpenAPITags, []string{"backup"}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter("name", "backup plan name").DataType("string").Required(true)).
		Returns(http.StatusOK, "", &response.Response{}))

	ws.Route(ws.DELETE("/backup/plans/{name}").
		To(handler.deleteBackupPlan).
		Doc("delete backup plan").
		Metadata(restfulspec.KeyOpenAPITags, []string{"backup"}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter("name", "backup plan name").DataType("string").Required(true)).
		Returns(http.StatusOK, "", &response.Response{}))

	ws.Route(ws.GET("/backup/plans/{plan_name}/snapshots").
		To(handler.listBackupSnapshots).
		Doc("list backup snapshots").
		Param(ws.QueryParameter("limit", "limit of snapshots").Required(false)).
		Metadata(restfulspec.KeyOpenAPITags, []string{"backup"}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter("plan_name", "backup plan name").DataType("string").Required(true)).
		Returns(http.StatusOK, "", &response.Response{}))

	ws.Route(ws.GET("/backup/plans/{plan_name}/snapshots/{name}").
		To(handler.describeBackupSnapshot).
		Doc("get backup snapshot details").
		Metadata(restfulspec.KeyOpenAPITags, []string{"backup"}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter("name", "backup snapshot name").DataType("string").Required(true)).
		Param(ws.PathParameter("plan_name", "backup plan name").DataType("string").Required(true)).
		Returns(http.StatusOK, "", &response.Response{}))

	ws.Route(ws.DELETE("/backup/plans/{plan_name}/snapshots/{name}").
		To(handler.deleteBackupSnapshot).
		Doc("delete backup snapshot by name").
		Metadata(restfulspec.KeyOpenAPITags, []string{"backup"}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Param(ws.PathParameter("name", "backup snapshot name").DataType("string").Required(true)).
		Param(ws.PathParameter("plan_name", "backup plan name").DataType("string").Required(true)).
		Returns(http.StatusOK, "", &response.Response{}))

	// GPU
	ws.Route(ws.GET("/gpu/managed-memory").
		To(handler.handleGetGpuManagedMemory).
		Doc("get gpu managed memory enabled or not").
		Metadata(restfulspec.KeyOpenAPITags, []string{"gpu"}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Returns(http.StatusOK, "", &response.Response{}))

	ws.Route(ws.POST("/gpu/enable/managed-memory").
		To(handler.handleEnableGpuManagedMemory).
		Doc("enable gpu managed memory").
		Metadata(restfulspec.KeyOpenAPITags, []string{"gpu"}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Returns(http.StatusOK, "", &response.Response{}))

	ws.Route(ws.POST("/gpu/disable/managed-memory").
		To(handler.handleDisableGpuManagedMemory).
		Doc("disable gpu managed memory").
		Metadata(restfulspec.KeyOpenAPITags, []string{"gpu"}).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Returns(http.StatusOK, "", &response.Response{}))

	c.Add(ws)
	return nil
}
