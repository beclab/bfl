package v1alpha1

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils"

	"github.com/emicklei/go-restful/v3"
	"k8s.io/klog"
)

const SYSTEM_UPGRADE_EVENT = "system-upgrade-event"
const (
	StatusFailed   = "failed"
	StatusRunning  = "running"
	StatusComplete = "completed"
	StatusStart    = "started"
)

func (h *Handler) newVersion(req *restful.Request, resp *restful.Response) {
	h.doSystemUpgradeFunc(req, resp, fnWrap2(h.appServiceClient.GetSystemNewVersion), nil)
}

func (h *Handler) upgradeState(req *restful.Request, resp *restful.Response) {
	h.doSystemUpgradeFunc(req, resp, fnWrap(h.appServiceClient.GetSystemUpgradeState), nil)
}
func (h *Handler) upgrade(req *restful.Request, resp *restful.Response) {
	pre := func(req *restful.Request, resp *restful.Response) {
		// send event to desktop
		if err := h.eventClient.CreateEvent(SYSTEM_UPGRADE_EVENT, "start to upgrade Terminus",
			map[string]string{
				"status": StatusStart,
			},
		); err != nil {
			klog.Error("send system upgrade event to desktop error, ", err)
		}

		go h.waitingForUpgrade(req)
	}

	h.doSystemUpgradeFunc(req, resp, fnWrap2(h.appServiceClient.SystemUpgrade), pre)
}
func (h *Handler) upgradeCancel(req *restful.Request, resp *restful.Response) {
	h.doSystemUpgradeFunc(req, resp, fnWrap(h.appServiceClient.SystemUpgradeCancel), nil)
}

func (h *Handler) doSystemUpgradeFunc(
	req *restful.Request,
	resp *restful.Response,
	fn func(args ...any) (map[string]interface{}, error),
	preResp func(req *restful.Request, resp *restful.Response),
) {
	// fetch token from request
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)
	mode := req.QueryParameter("dev_mode")
	var (
		result map[string]interface{}
		err    error
	)

	if mode == "" {
		result, err = fn(token)
	} else {
		result, err = fn(token, mode == "true")
	}
	if err != nil {
		// when sytem upgrading, app-service may be down, so we need to tell the frontend
		// with a error status code
		resp.WriteError(http.StatusNotFound, err)
		return
	}

	if preResp != nil {
		preResp(req, resp)
	}

	resp.WriteAsJson(result)
}

func (h *Handler) waitingForUpgrade(req *restful.Request) {
	ticker := time.NewTicker(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)

	defer func() {
		ticker.Stop()
		cancel()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			token := req.Request.Header.Get(constants.AuthorizationTokenKey)
			result, err := h.appServiceClient.GetSystemUpgradeState(token)
			if err != nil {
				klog.Error("get system upgrade status error, ", err)
				continue
			}

			data := &struct {
				State string `json:"state"`
			}{}
			resp := response.Response{
				Data: data,
			}

			err = h.appServiceClient.UnmarshalResult(result, &resp)
			if err != nil {
				klog.Error("unmarshal system upgrade status error, ", err)
				continue
			}

			klog.Info("get upgrade status")
			klog.Info(utils.PrettyJSON(result))
			klog.Info(utils.PrettyJSON(resp))

			if resp.Code == 0 && (data.State == StatusComplete || data.State == StatusFailed) {
				if err := h.eventClient.CreateEvent(SYSTEM_UPGRADE_EVENT,
					fmt.Sprintf("%s to upgrade Terminus", data.State),
					map[string]string{
						"status": data.State,
					},
				); err != nil {
					klog.Error("send event (upgrade status change) to desktop error,", err)
				} else {
					return
				}
			}
		}
	}

}

func fnWrap(f func(string) (map[string]interface{}, error)) func(a ...any) (map[string]interface{}, error) {
	return func(a ...any) (map[string]interface{}, error) {
		return f(a[0].(string))
	}
}

func fnWrap2(f func(string, bool) (map[string]interface{}, error)) func(a ...any) (map[string]interface{}, error) {
	return func(a ...any) (map[string]interface{}, error) {
		m := false
		if len(a) > 1 {
			m = a[1].(bool)
		}
		return f(a[0].(string), m)
	}
}
