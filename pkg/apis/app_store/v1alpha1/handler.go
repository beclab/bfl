package v1alpha1

import (
	"fmt"
	"net/url"
	"strconv"

	"bytetrade.io/web3os/bfl/pkg/api"
	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/app_service/v1"
	v1alpha1client "bytetrade.io/web3os/bfl/pkg/client/clientset/v1alpha1"
	"bytetrade.io/web3os/bfl/pkg/constants"

	"github.com/emicklei/go-restful/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

type Handler struct {
	appServiceClient *app_service.Client
	watchDogManager  WatchDogManager
}

func newHandler() *Handler {
	return &Handler{
		appServiceClient: app_service.NewAppServiceClient(),
		watchDogManager:  NewWatchDogManager(),
	}
}

func (h *Handler) handleList(req *restful.Request, resp *restful.Response) {

	// fetch installed apps from app service
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)

	iapps, err := h.appServiceClient.FetchAppList(token)
	if err != nil {
		response.HandleUnauthorized(resp, err)
		return
	}

	installedApp := make(map[string]map[string]interface{})
	for _, iapp := range iapps {
		iappSpec := iapp["spec"].(map[string]interface{})
		iappName := iappSpec["name"].(string)
		installedApp[iappName] = iapp
	}

	var appList []*ApplicationInfo

	apps, err := h.appServiceClient.FetchRegistryList(token)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	query := req.Request.URL.Query()
	if search, ok := query["q"]; ok && len(search) > 0 && search[0] != "" {
		// TODO: search result
		response.Success(resp, api.NewListResult(appList))
		return
	}

	pageFunc := func(f string, defaultValue int) int {
		if o, ok := query[f]; ok {
			v, e := strconv.Atoi(o[0])
			if e != nil {
				klog.Error("parse query param error, ", f, " ", e)
				v = defaultValue
			}

			delete(query, f)

			return v
		}

		return defaultValue
	}

	offset := pageFunc(ParamOffset, 0)
	limit := pageFunc(ParamLimit, 100)

	for _, a := range apps {
		appMeta := a["metadata"].(map[string]interface{})
		if !appFilter(appMeta, query) {
			continue
		}

		appInfo := getAppInfofromData(a, installedApp)

		appList = append(appList, appInfo)
	}

	min := func(x, y int) int {
		if x < y {
			return x
		}
		return y
	}

	if offset >= len(appList) {
		response.Success(resp, api.NewListResult([]*ApplicationInfo{}))
		return
	}

	end := min(len(appList), offset+limit)
	response.Success(resp, api.NewListResult(appList[offset:end]))
}

func (h *Handler) handleGetDetail(req *restful.Request, resp *restful.Response) {

	// fetch installed apps from app service
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)
	appname := req.PathParameter(ParamAppName)

	app, err := h.appServiceClient.FetchAppDetail(appname, token)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	iapps, err := h.appServiceClient.FetchAppList(token)
	if err != nil {
		response.HandleUnauthorized(resp, err)
		return
	}

	installedApp := make(map[string]map[string]interface{})
	for _, iapp := range iapps {
		iappSpec := iapp["spec"].(map[string]interface{})
		iappName := iappSpec["name"].(string)
		installedApp[iappName] = iapp
	}

	appInfo := getAppInfofromData(app, installedApp)
	response.Success(resp, appInfo)
}

func (h *Handler) install(req *restful.Request, resp *restful.Response) {
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)
	appname := req.PathParameter(ParamAppName)

	h._install(resp, appname, token, nil)
}

func (h *Handler) installDev(req *restful.Request, resp *restful.Response) {
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)

	// provider api
	// opt in providerrequest.data actually
	var opt ProviderRequest
	if err := req.ReadEntity(&opt); err != nil {
		response.HandleError(resp, err)
		return
	}

	// Find app in helm list. If exists do upgrade, or do install
	kubeClient := v1alpha1client.KubeClient.Kubernetes()
	namespace := opt.Data.App + "-" + constants.Username
	helmName := fmt.Sprintf("sh.helm.release.v1.%s.v1", opt.Data.App)
	_, err := kubeClient.CoreV1().Secrets(namespace).Get(req.Request.Context(), helmName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		response.HandleError(resp, err)
		return
	}

	if err == nil {
		// upgrade
		data, err := h.appServiceClient.UpgradeApp(opt.Data.App, token, &app_service.UpgradeOptions{
			CfgURL:  opt.Data.CfgURL,
			RepoURL: opt.Data.RepoURL,
			Version: "",
			Source:  opt.Data.Source,
		})
		if err != nil {
			response.HandleError(resp, err)
			return
		}
		uidData := data["data"].(map[string]interface{})
		uid := uidData["uid"].(string)

		response.Success(resp, &InstallationResponse{
			UID: uid,
		})
	} else {
		h._install(resp, opt.Data.App, token, opt.Data)
	}
}

func (h *Handler) _install(resp *restful.Response, appname, token string, opt *app_service.InstallOptions) {
	data, err := h.appServiceClient.InstallApp(appname, token, opt)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	uidData := data["data"].(map[string]interface{})
	uid := uidData["uid"].(string)

	go h.watchDogManager.NewWatchDog(OP_INSTALL,
		appname, uid, token,
		h.appServiceClient).
		Exec()

	response.Success(resp, &InstallationResponse{
		UID: uid,
	})
}

func (h *Handler) uninstall(req *restful.Request, resp *restful.Response) {
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)
	appname := req.PathParameter(ParamAppName)

	data, err := h.appServiceClient.UninstallApp(appname, token)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	uidData := data["data"].(map[string]interface{})
	uid := uidData["uid"].(string)

	go h.watchDogManager.NewWatchDog(OP_UNINSTALL,
		appname, uid, token,
		h.appServiceClient).
		Exec()

	response.Success(resp, &InstallationResponse{
		UID: uid,
	})
}

func (h *Handler) status(req *restful.Request, resp *restful.Response) {
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)
	uid := req.PathParameter(ParamInstallationId)

	data, err := h.appServiceClient.AppInstallStatus(uid, token)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	statusData := data["data"].(map[string]interface{})
	status := statusData["status"].(string)

	response.Success(resp, &InstallationStatusResp{
		UID:    uid,
		Status: status,
	})
}

func (h *Handler) cancel(req *restful.Request, resp *restful.Response) {
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)
	uid := req.PathParameter(ParamInstallationId)

	_, err := h.appServiceClient.AppInstallCancel(uid, token)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	response.Success(resp, &InstallationResponse{
		UID: uid,
	})
}

func getAppInfofromData(app map[string]interface{},
	installedApp map[string]map[string]interface{}) *ApplicationInfo {
	appMeta := app["metadata"].(map[string]interface{})
	appSpec := app["spec"]
	appSC := getOrEmpty(appSpec, "supportClient")
	appInfo := &ApplicationInfo{
		Name:        getStringOrEmpty(appMeta, "name"),
		Icon:        getStringOrEmpty(appMeta, "icon"),
		Description: getStringOrEmpty(appMeta, "description"),
		AppID:       getStringOrEmpty(appMeta, "appid"),
		Title:       getStringOrEmpty(appMeta, "title"),
		Version:     getStringOrEmpty(appMeta, "version"),
		Categories:  getStringFromListOrEmpty(appMeta, "categories"),
		Rating:      getFloat32OrEmpty(appMeta, "rating"),

		VersionName:        getStringOrEmpty(appSpec, "versionName"),
		FullDescription:    getStringOrEmpty(appSpec, "fullDescription"),
		UpgradeDescription: getStringOrEmpty(appSpec, "upgradeDescription"),
		PromoteImage:       getStringListOrEmpty(appSpec, "promoteImage"),
		PromoteVideo:       getStringOrEmpty(appSpec, "promoteVideo"),
		SubCategory:        getStringOrEmpty(appSpec, "subCategory"),
		Developer:          getStringOrEmpty(appSpec, "developer"),
		RequiredMemory:     getStringOrEmpty(appSpec, "requiredMemory"),
		RequiredDisk:       getStringOrEmpty(appSpec, "requiredDisk"),
		RequiredCPU:        getStringOrEmpty(appSpec, "requiredCpu"),
		RequiredGPU:        getStringOrEmpty(appSpec, "requiredGpu"),
		SupportClient: SupportClient{
			Edge:    getStringOrEmpty(appSC, "edge"),
			Android: getStringOrEmpty(appSC, "android"),
			Ios:     getStringOrEmpty(appSC, "ios"),
			Windows: getStringOrEmpty(appSC, "windows"),
			Mac:     getStringOrEmpty(appSC, "mac"),
			Linux:   getStringOrEmpty(appSC, "linux"),
		},
	}
	// find app status from app service
	// TODO: 1, more status 2, instead of app id
	if _, ok := installedApp[appInfo.Name]; ok {
		appInfo.Status = APP_INSTALLED
	} else {
		appInfo.Status = APP_UNINSTALLED
	}

	return appInfo
}

func getFloat32OrEmpty(m any, k string) float32 {
	if m == nil {
		return 0.0
	}

	data := m.(map[string]interface{})

	if v, ok := data[k]; ok {
		return float32(v.(float64))
	}
	return 0.0
}

func getBoolOrEmpty(m any, k string) bool {
	if m == nil {
		return false
	}

	data := m.(map[string]interface{})

	if v, ok := data[k]; ok {
		return bool(v.(bool))
	}
	return false
}

// func getInt32OrEmpty(m any, k string) int32 {
// 	if m == nil {
// 		return 0
// 	}

// 	data := m.(map[string]interface{})

// 	if v, ok := data[k]; ok {
// 		return int32(v.(float64))
// 	} else {
// 		return 0
// 	}
// }

func getStringOrEmpty(m any, k string) string {
	if m == nil {
		return ""
	}

	data := m.(map[string]interface{})

	if v, ok := data[k]; ok {
		return v.(string)
	}
	return ""
}

func getStringFromListOrEmpty(m any, k string) string {
	if m == nil {
		return ""
	}

	data := m.(map[string]interface{})

	if v, ok := data[k]; ok && v != nil {
		va := v.([]interface{})
		if len(va) > 0 {
			return va[0].(string)
		}
		return ""
	}
	return ""
}

func getStringListOrEmpty(m any, k string) []string {
	if m == nil {
		return nil
	}

	data := m.(map[string]interface{})

	if v, ok := data[k]; ok && v != nil {
		var ret []string
		for _, s := range v.([]interface{}) {
			ret = append(ret, s.(string))
		}
		return ret
	}
	return nil
}

func getOrEmpty(m any, k string) any {
	if m == nil {
		return nil
	}

	data := m.(map[string]interface{})

	return data[k]
}

func appFilter(appMeta map[string]interface{}, query url.Values) bool {
	if query == nil {
		return true
	}

	for q, v := range query {
		if f, ok := appMeta[q]; ok {
			var field string

			switch f := f.(type) {
			// just app metadata can be filtered
			case string:
				field = f
			case []interface{}: // categories,
				field = getStringFromListOrEmpty(appMeta, q)
			}

			found := false
			for _, s := range v {
				if s == field {
					found = true
				}
			}

			if !found {
				return false
			}
		}

	}

	return true
}
