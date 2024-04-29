package v1alpha1

import (
	"net/http"

	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"

	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	"github.com/emicklei/go-restful/v3"
)

const (
	ok         = "OK"
	ParamKey   = "key"
	ParamValue = "value"
)

var (
	MODULE_TAGS = []string{"datastore"}
)

var ModuleVersion = runtime.ModuleVersion{Name: "datastore", Version: "v1alpha1"}

func AddToContainer(c *restful.Container) error {
	ws := runtime.NewWebService(ModuleVersion)
	handler, filters, err := New()
	if err != nil {
		return err
	}

	for _, f := range filters {
		ws.Filter(f.filter)
	}

	ws.Route(ws.POST("/get").
		To(handler.handleGetKey).
		Doc("Get the data of a key ( provider )").
		Metadata(restfulspec.KeyOpenAPITags, MODULE_TAGS).
		Returns(http.StatusOK, ok, response.Response{}))

	ws.Route(ws.POST("/get/prefix").
		To(handler.handleGetKeyPrefix).
		Doc("Multi get the data with a key prefix ( provider )").
		Metadata(restfulspec.KeyOpenAPITags, MODULE_TAGS).
		Returns(http.StatusOK, ok, response.Response{}))

	ws.Route(ws.POST("/put").
		To(handler.handleSet).
		Doc("Set the data of a key ( provider )").
		Metadata(restfulspec.KeyOpenAPITags, MODULE_TAGS).
		Returns(http.StatusOK, ok, response.Response{}))

	ws.Route(ws.POST("/delete").
		To(handler.handleDelete).
		Doc("Delete the data of a key ( provider )").
		Metadata(restfulspec.KeyOpenAPITags, MODULE_TAGS).
		Returns(http.StatusOK, ok, response.Response{}))

	c.Add(ws)
	return nil
}
