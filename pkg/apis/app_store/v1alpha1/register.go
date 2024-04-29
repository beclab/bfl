package v1alpha1

import (
	"net/http"

	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/constants"

	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
)

const (
	APIRootPath         = "/app-store"
	Version             = "v1"
	ParamAppName        = "appname"
	ParamInstallationId = "iuid"
	ParamCategory       = "categories"
	ParamSearch         = "q"
	ParamOffset         = "offset"
	ParamLimit          = "limit"
)

var (
	MODULE_TAGS = []string{"app-store"}
)

var ModuleVersion = runtime.ModuleVersion{Name: "app_store", Version: "v1alpha1"}

func AddToContainer(c *restful.Container) error {
	ws := runtime.NewWebService(ModuleVersion)
	handler := newHandler()

	ws.Route(ws.POST("/applications/installdev").
		To(handler.installDev).
		Doc("Install the dev mode application (Only for Provider) ").
		Metadata(restfulspec.KeyOpenAPITags, MODULE_TAGS).
		Param(ws.PathParameter(ParamAppName, "the name of a application")).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token")).
		Reads(ProviderRequest{}).
		Returns(http.StatusOK, "Success to begin a installation of the application", &InstallationResponse{}))

	ws.Route(ws.POST("/applications/{"+ParamAppName+"}/uninstall").
		To(handler.uninstall).
		Doc("Uninstall the application").
		Metadata(restfulspec.KeyOpenAPITags, MODULE_TAGS).
		Param(ws.PathParameter(ParamAppName, "the name of a application")).
		Param(ws.HeaderParameter(constants.AuthorizationTokenKey, "Auth token")).
		Returns(http.StatusOK, "Success to begin a uninstallation of the application", &InstallationResponse{}))

	c.Add(ws)
	return nil
}
