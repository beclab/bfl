package v1alpha1

import (
	"errors"
	"fmt"

	"bytetrade.io/web3os/bfl/pkg/api"
	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/apis"
	"bytetrade.io/web3os/bfl/pkg/app_service/v1"
	"bytetrade.io/web3os/bfl/pkg/constants"

	"github.com/emicklei/go-restful/v3"
)

type Handler struct {
	apis.Base
	appService *app_service.Client
}

// TODO: response OK msg
type OK struct {
	Code int `json:"code"`
}

var (
	ErrDeploymentNotFound = errors.New("app not found")
	ErrOperationIllegal   = errors.New("illegal operation")
)

func newHandler() (*Handler, error) {
	as := app_service.NewAppServiceClient()
	return &Handler{
		appService: as,
	}, nil
}

func (h *Handler) handleLaunch(req *restful.Request, resp *restful.Response) {
	appName := req.PathParameter(ParamAppName)
	token := req.HeaderParameter(constants.AuthorizationTokenKey)
	if _, err := h.appService.ResumeApp(appName, token); err != nil {
		response.HandleError(resp, fmt.Errorf("launch app: %v", err))
	}
	response.SuccessNoData(resp)
}

func (h *Handler) handleClose(req *restful.Request, resp *restful.Response) {
	appName := req.PathParameter(ParamAppName)
	token := req.HeaderParameter(constants.AuthorizationTokenKey)
	if _, err := h.appService.SuspendApp(appName, token); err != nil {
		response.HandleError(resp, fmt.Errorf("suspend app: %v", err))
	}
	response.SuccessNoData(resp)
}

func (h *Handler) handleListApps(req *restful.Request, resp *restful.Response) {
	list, err := h.Base.GetAppListAndServicePort(req, h.appService,
		func() (string, []*app_service.AppInfo, error) { return h.Base.GetAppViaToken(req, h.appService) })
	if err != nil {
		response.HandleInternalError(resp, fmt.Errorf("list apps: %v", err))
		return
	}
	response.Success(resp, api.NewListResult(list))
}

func (h *Handler) handleListAllApps(req *restful.Request, resp *restful.Response) {
	list, err := h.Base.GetAppListAndServicePort(req, h.appService,
		func() (string, []*app_service.AppInfo, error) { return h.Base.GetAllAppViaToken(req, h.appService) })
	if err != nil {
		response.HandleInternalError(resp, fmt.Errorf("list apps: %v", err))
		return
	}
	userAppMap := make(map[string][]*app_service.AppInfo)
	for _, u := range list {
		userAppMap[u.Owner] = append(userAppMap[u.Owner], u)
	}

	//response.Success(resp, api.NewListResult(list))
	response.Success(resp, userAppMap)
}
