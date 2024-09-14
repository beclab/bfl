package v1alpha1

import (
	"net/http"

	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/constants"

	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
)

const (
	ParamAppName               = "appname"
	ParamAppNamespace          = "appnamespace"
	AttributeAppDeploymentInfo = "appdeployment"
	AttributeDeploymentsClient = "deployments"
)

var (
	MODULE_TAGS = []string{"app_process"}
)

var ModuleVersion = runtime.ModuleVersion{Name: "app_process", Version: "v1alpha1"}

func AddToContainer(c *restful.Container) error {
	ws := runtime.NewWebService(ModuleVersion)
	handler, _ := newHandler()

	ws.Route(ws.POST("/launch/{"+ParamAppName+"}").
		To(handler.handleLaunch).
		Doc("Launch a app with the configurations").
		Metadata(restfulspec.KeyOpenAPITags, MODULE_TAGS).
		Param(ws.PathParameter(ParamAppName, "App name to be launched")).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Returns(http.StatusOK, "Success to send a launch message", response.Response{}))

	ws.Route(ws.POST("/close/{"+ParamAppName+"}").
		To(handler.handleClose).
		Doc("Close the app").
		Metadata(restfulspec.KeyOpenAPITags, MODULE_TAGS).
		Param(ws.PathParameter(ParamAppName, "App name to be closed")).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Returns(http.StatusOK, "Success to send a close message", response.Response{}))

	ws.Route(ws.GET("/myapps").
		To(handler.handleListApps).
		Doc("List user's apps").
		Metadata(restfulspec.KeyOpenAPITags, MODULE_TAGS).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Returns(http.StatusOK, "UserName's app list", response.Response{}))

	ws.Route(ws.GET("/allapps").
		To(handler.handleListAllApps).
		Doc("List all user's apps").
		Metadata(restfulspec.KeyOpenAPITags, MODULE_TAGS).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token").Required(true)).
		Returns(http.StatusOK, "all user's app list", response.Response{}))

	c.Add(ws)
	return nil
}
