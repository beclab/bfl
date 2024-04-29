package v1alpha1

import "bytetrade.io/web3os/bfl/pkg/app_service/v1"

type AppStatus string

const (
	APP_INSTALLED    AppStatus = "installed"
	APP_RUNNING      AppStatus = "running"
	APP_INSTALLING   AppStatus = "installing"
	APP_UNINSTALLED  AppStatus = "uninstalled"
	APP_UNINSTALLING AppStatus = "uninstalling"
)

type ApplicationInfo struct {
	Name               string        `json:"name"`
	Icon               string        `json:"icon"`
	Description        string        `json:"desc"`
	AppID              string        `json:"appid"`
	Title              string        `json:"title"`
	Version            string        `json:"version"`
	Categories         string        `json:"categories"`
	Status             AppStatus     `json:"status"`
	VersionName        string        `json:"versionName"`
	FullDescription    string        `json:"fullDescription"`
	UpgradeDescription string        `json:"upgradeDescription"`
	PromoteImage       []string      `json:"promoteImage"`
	PromoteVideo       string        `json:"promoteVideo"`
	SubCategory        string        `json:"subCategory"`
	Developer          string        `json:"developer"`
	RequiredMemory     string        `json:"requiredMemory"`
	RequiredDisk       string        `json:"requiredDisk"`
	SupportClient      SupportClient `json:"supportClient"`
	Rating             float32       `json:"rating"`
	RequiredGPU        string        `json:"requiredGpu"`
	RequiredCPU        string        `json:"requiredCpu"`
}

type SupportClient struct {
	Edge    string `json:"edge"`
	Android string `json:"android"`
	Ios     string `json:"ios"`
	Windows string `json:"windows"`
	Mac     string `json:"mac"`
	Linux   string `json:"linux"`
}

func (as AppStatus) Show() string {
	switch as {
	case APP_INSTALLED:
		return "Uninstall"
	case APP_RUNNING:
		return "Close"
	case APP_INSTALLING:
		return "Cancel"
	case APP_UNINSTALLED:
		return "Install"
	case APP_UNINSTALLING:
		return "Cancel"
	}

	return "Install"
}

type ProviderRequest struct {
	Op       string                      `json:"op"`
	DataType string                      `json:"datatype"`
	Version  string                      `json:"version"`
	Group    string                      `json:"group"`
	Param    interface{}                 `json:"param,omitempty"`
	Data     *app_service.InstallOptions `json:"data,omitempty"`
	Token    string
}
