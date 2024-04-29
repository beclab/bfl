package app_service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type Client struct {
	httpClient *http.Client
}

const (
	AppServiceGetURLTempl                  = "http://%s:%s/app-service/v1/apps/%s"
	AppServiceListURLTempl                 = "http://%s:%s/app-service/v1/apps"
	AppServiceUserAppListURLTempl          = "http://%s:%s/app-service/v1/user-apps/%s"
	AppServiceRegistryListURLTempl         = "http://%s:%s/app-service/v1/registry/applications"
	AppServiceAppDetailURLTempl            = "http://%s:%s/app-service/v1/registry/applications/%s"
	AppServiceInstallURLTempl              = "http://%s:%s/app-service/v1/apps/%s/install"
	AppServiceUpgradeAppURLTempl           = "http://%s:%s/app-service/v1/apps/%s/upgrade"
	AppServiceUninstallURLTempl            = "http://%s:%s/app-service/v1/apps/%s/uninstall"
	AppServiceInstallStatusURLTempl        = "http://%s:%s/app-service/v1/apps/%s/operate"
	AppServiceCancelInstallURLTempl        = "http://%s:%s/app-service/v1/apps/%s/cancel"
	AppServiceUserAppsInstallURLTempl      = "http://%s:%s/app-service/v1/users/apps/create/%s"
	AppServiceUserAppsUninstallURLTempl    = "http://%s:%s/app-service/v1/users/apps/delete/%s"
	AppServiceUserAppsStatusURLTempl       = "http://%s:%s/app-service/v1/users/apps/%s"
	AppServiceSystemServiceEnableURLTempl  = "http://%s:%s/app-service/v1/system/service/enable/%s"
	AppServiceSystemServiceDisableURLTempl = "http://%s:%s/app-service/v1/system/service/disable/%s"
	AppServiceAppSetupURLTempl             = "http://%s:%s/app-service/v1/applications/%s/setup"
	AppServiceAppEntrancesURLTempl         = "http://%s:%s/app-service/v1/applications/%s/entrances"
	AppServiceAppEntranceSetupURLTempl     = "http://%s:%s/app-service/v1/applications/%s/%s/setup"
	AppServiceAppEntranceAuthURLTempl      = "http://%s:%s/app-service/v1/applications/%s/%s/auth-level"
	AppServiceAppEntrancePolicyURLTempl    = "http://%s:%s/app-service/v1/applications/%s/%s/policy"
	AppServiceUpgradeNewVersionURLTempl    = "http://%s:%s/app-service/v1/upgrade/newversion"
	AppServiceUpgradeStateURLTempl         = "http://%s:%s/app-service/v1/upgrade/state"
	AppServiceUpgradeURLTempl              = "http://%s:%s/app-service/v1/upgrade"
	AppServiceUpgradeCancelURLTempl        = "http://%s:%s/app-service/v1/upgrade/cancel"
	AppServiceUserMetricsURLTempl          = "http://%s:%s/app-service/v1/users/%s/metrics"
	AppServiceAppInstallationRunningList   = "http://%s:%s/app-service/v1/apps/pending-installing/task"

	AppServiceAppSuspendURLTempl = "http://%s:%s/app-service/v1/apps/%s/suspend"
	AppServiceAppResumeURLTempl  = "http://%s:%s/app-service/v1/apps/%s/resume"

	AppServiceHostEnv = "APP_SERVICE_SERVICE_HOST"
	AppServicePortEnv = "APP_SERVICE_SERVICE_PORT"
)

func NewAppServiceClient() *Client {
	transport := &http.Transport{
		MaxIdleConnsPerHost: 50,
	}
	c := &Client{
		httpClient: &http.Client{Timeout: time.Second * 5,
			Transport: transport},
	}

	return c
}

func (c *Client) GetAppInfo(appname, token string) (*AppInfo, error) {
	app, err := c.fetchAppInfoFromAppService(appname, token)
	if err != nil {
		return nil, err
	}

	return c.getAppInfoFromData(app)
}

func (c *Client) ListAppInfosByOwner(token string) ([]*AppInfo, error) {
	app, err := c.FetchAppList(token)
	if err != nil {
		return nil, err
	}

	return c.getAppListFromData(app)
}

func (c *Client) ListAppInfosByUser(user string) ([]*AppInfo, error) {
	app, err := c.FetchUserAppList(user)
	if err != nil {
		return nil, err
	}

	return c.getAppListFromData(app)
}

func (c *Client) FetchAppList(token string) ([]map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceListURLTempl, appServiceHost, appServicePort)

	return c.doHttpGetList(urlStr, token)
}

func (c *Client) FetchUserAppList(user string) ([]map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceUserAppListURLTempl, appServiceHost, appServicePort, user)

	return c.doHttpGetList(urlStr, "")
}

func (c *Client) FetchRegistryList(token string) ([]map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceRegistryListURLTempl, appServiceHost, appServicePort)

	return c.doHttpGetList(urlStr, token)
}

func (c *Client) FetchAppDetail(appname, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceAppDetailURLTempl, appServiceHost, appServicePort, appname)

	return c.doHttpGetOne(urlStr, token)
}

func (c *Client) InstallApp(appname, token string, options *InstallOptions) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceInstallURLTempl, appServiceHost, appServicePort, appname)

	return c.doHttpPost(urlStr, token, options)
}

func (c *Client) UpgradeApp(appname, token string, options *UpgradeOptions) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceUpgradeAppURLTempl, appServiceHost, appServicePort, appname)

	return c.doHttpPost(urlStr, token, options)
}

func (c *Client) UninstallApp(appname, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceUninstallURLTempl, appServiceHost, appServicePort, appname)

	return c.doHttpPost(urlStr, token, nil)
}

func (c *Client) AppInstallStatus(installUid, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceInstallStatusURLTempl, appServiceHost, appServicePort, installUid)

	return c.doHttpGetOne(urlStr, token)
}

func (c *Client) AppInstallCancel(installUid, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceCancelInstallURLTempl, appServiceHost, appServicePort, installUid)

	return c.doHttpPost(urlStr, token, nil)
}

func (c *Client) InstallUserApps(user, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceUserAppsInstallURLTempl, appServiceHost, appServicePort, user)

	return c.doHttpPost(urlStr, token, nil)
}

func (c *Client) UninstallUserApps(user, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceUserAppsUninstallURLTempl, appServiceHost, appServicePort, user)

	return c.doHttpPost(urlStr, token, nil)
}

func (c *Client) UserAppsStatus(user, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceUserAppsStatusURLTempl, appServiceHost, appServicePort, user)

	return c.doHttpGetOne(urlStr, token)
}

func (c *Client) EnableSystemService(service, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceSystemServiceEnableURLTempl, appServiceHost, appServicePort, service)

	return c.doHttpPost(urlStr, token, nil)
}

func (c *Client) DisableSystemService(service, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceSystemServiceDisableURLTempl, appServiceHost, appServicePort, service)

	return c.doHttpPost(urlStr, token, nil)
}

func (c *Client) SetupAppPolicy(app, token string, settings ApplicationsSettings) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceAppSetupURLTempl, appServiceHost, appServicePort, app)

	return c.doHttpPost(urlStr, token, settings)
}

func (c *Client) SetupAppEntrancePolicy(app, entranceName, token string, settings ApplicationsSettings) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceAppEntrancePolicyURLTempl, appServiceHost, appServicePort, app, entranceName)

	return c.doHttpPost(urlStr, token, settings)
}

func (c *Client) GetAppPolicy(app, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceAppSetupURLTempl, appServiceHost, appServicePort, app)

	return c.doHttpGetOne(urlStr, token)
}

func (c *Client) SetupAppCustomDomain(app, entranceName, token string, settings ApplicationsSettings) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceAppEntranceSetupURLTempl, appServiceHost, appServicePort, app, entranceName)

	return c.doHttpPost(urlStr, token, settings)
}

func (c *Client) GetAppCustomDomain(app, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceAppSetupURLTempl, appServiceHost, appServicePort, app)

	return c.doHttpGetOne(urlStr, token)
}

func (c *Client) GetAppEntrances(app, token string) ([]map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceAppEntrancesURLTempl, appServiceHost, appServicePort, app)
	return c.doHttpGetList(urlStr, token)
}

func (c *Client) SetupAppAuthorizationLevel(app, entranceName, token string, settings ApplicationsSettings) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceAppEntranceAuthURLTempl, appServiceHost, appServicePort, app, entranceName)

	return c.doHttpPost(urlStr, token, settings)
}

func (c *Client) GetAppAuthorizationLevel(app, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceAppSetupURLTempl, appServiceHost, appServicePort, app)

	return c.doHttpGetOne(urlStr, token)
}

func (c *Client) GetSystemNewVersion(token string, devMode bool) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceUpgradeNewVersionURLTempl, appServiceHost, appServicePort)
	if devMode {
		urlStr += "?dev_mode=true"
	}

	return c.doHttpGetOne(urlStr, token)
}

func (c *Client) GetSystemUpgradeState(token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceUpgradeStateURLTempl, appServiceHost, appServicePort)

	return c.doHttpGetOne(urlStr, token)
}

func (c *Client) SystemUpgrade(token string, devMode bool) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceUpgradeURLTempl, appServiceHost, appServicePort)
	if devMode {
		urlStr += "?dev_mode=true"
	}

	return c.doHttpPost(urlStr, token, nil)
}

func (c *Client) SystemUpgradeCancel(token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceUpgradeCancelURLTempl, appServiceHost, appServicePort)

	return c.doHttpPost(urlStr, token, nil)
}

func (c *Client) UnmarshalResult(result map[string]interface{}, unmarshaled any) error {
	s, err := json.Marshal(result)
	if err != nil {
		return err
	}

	return json.Unmarshal(s, unmarshaled)
}

func (c *Client) GetUserMetrics(user, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceUserMetricsURLTempl, appServiceHost, appServicePort, user)

	return c.doHttpGetOne(urlStr, token)
}

func (c *Client) GetInstallationRunningList(token string) ([]map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceAppInstallationRunningList, appServiceHost, appServicePort)
	return c.doHttpGetList(urlStr, token)
}

func (c *Client) SuspendApp(appName, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceAppSuspendURLTempl, appServiceHost, appServicePort, appName)

	return c.doHttpPost(urlStr, token, nil)
}

func (c *Client) ResumeApp(appName, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceAppResumeURLTempl, appServiceHost, appServicePort, appName)

	return c.doHttpPost(urlStr, token, nil)
}
