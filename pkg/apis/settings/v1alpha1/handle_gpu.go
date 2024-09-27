package v1alpha1

import (
	"errors"

	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/app_service/v1"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"github.com/emicklei/go-restful/v3"
)

func (h *Handler) handleEnableGpuManagedMemory(req *restful.Request, resp *restful.Response) {
	// fetch token from request
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)

	admin, err := h.IsAdminUser(req.Request.Context())
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	if !admin {
		response.HandleForbidden(resp, errors.New("not an admin user"))
		return
	}

	appServiceClient := app_service.NewAppServiceClient()

	ret, err := appServiceClient.EnableGpuManagedMemory(token)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	response.Success(resp, ret)

}

func (h *Handler) handleDisableGpuManagedMemory(req *restful.Request, resp *restful.Response) {
	// fetch token from request
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)

	admin, err := h.IsAdminUser(req.Request.Context())
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	if !admin {
		response.HandleForbidden(resp, errors.New("not an admin user"))
		return
	}

	appServiceClient := app_service.NewAppServiceClient()

	ret, err := appServiceClient.DisableGpuManagedMemory(token)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	response.Success(resp, ret)
}

func (h *Handler) handleGetGpuManagedMemory(req *restful.Request, resp *restful.Response) {
	// fetch token from request
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)

	appServiceClient := app_service.NewAppServiceClient()

	ret, err := appServiceClient.GetGpuManagedMemory(token)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	response.Success(resp, ret)
}
