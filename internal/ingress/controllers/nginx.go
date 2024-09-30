package controllers

import (
	"fmt"

	"bytetrade.io/web3os/bfl/internal/ingress/controllers/config"
	"bytetrade.io/web3os/bfl/pkg/analytics"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils"

	"k8s.io/klog/v2"
)

var nonAppServers = []NonAppServer{
	{
		Name:             "auth",
		SvcEndpoint:      "http://authelia-svc.%s.svc.cluster.local:80",
		AuthEnabled:      false,
		AnalyticsEnabled: false,
	},
	{
		Name:             "desktop",
		SvcEndpoint:      "http://edge-desktop.%s.svc.cluster.local:80",
		AuthEnabled:      true,
		AnalyticsEnabled: true,
	},
	{
		Name:             "wizard",
		SvcEndpoint:      "http://wizard.%s.svc.cluster.local:80",
		AuthEnabled:      true,
		AnalyticsEnabled: false,
	},
}

type NonAppServer struct {
	Name             string
	LocationPrefix   string
	SvcEndpoint      string
	AuthEnabled      bool
	AnalyticsEnabled bool
}

func (r *NginxController) genNonAppServers(zone string, isEphemeral bool, language string) []config.Server {
	servers := make([]config.Server, 0)
	client := analytics.NewClient()
	for _, app := range nonAppServers {
		hostname := fmt.Sprintf("%s.%s", app.Name, zone)
		localHostname := fmt.Sprintf("%s.local.%s", app.Name, zone)
		if isEphemeral {
			hostname = fmt.Sprintf("%s-%s.%s", app.Name, constants.Username, zone)
			localHostname = fmt.Sprintf("%s-%s.local.%s", app.Name, constants.Username, zone)
		}

		var enableAnalytics bool
		var analyticsScript string

		if app.AnalyticsEnabled == true {
			resp, err := client.GetAnalyticsID(app.Name, app.Name, constants.Username)
			if err != nil {
				klog.Warningf("Failed to get analytics id, %v", err)
			} else {
				r, err := analytics.GetAnalyticsScript(zone, resp.ID)
				if err != nil {
					klog.Warningf("Failed to get analytics script, %v", err)
				} else {
					analyticsScript = r
					enableAnalytics = true
				}
			}
		}

		servers = append(servers, config.Server{
			Hostname:   hostname,
			Aliases:    []string{localHostname},
			EnableAuth: app.AuthEnabled,
			EnableSSL:  true,
			Locations: []config.Location{
				{
					Prefix:    utils.StringOrDefault(app.LocationPrefix, "/"),
					ProxyPass: fmt.Sprintf(app.SvcEndpoint, constants.Namespace),
				},
			},
			EnableAnalytics: enableAnalytics,
			AnalyticsScript: analyticsScript,
			Language:        language,
		})
	}
	return servers
}

func (r *NginxController) addDomainServers(isEphemeral bool, zone string, language string) []config.Server {
	servers := make([]config.Server, 0)
	client := analytics.NewClient()

	profile := config.Server{
		Hostname:  zone,
		Aliases:   []string{"local." + zone},
		EnableSSL: true,
		Locations: []config.Location{
			{
				Prefix:    "/",
				ProxyPass: fmt.Sprintf(constants.IndexAppEndpoint, constants.Username),
			},
		},
		EnableAuth: false,
		Language:   language,
	}

	// add analytics to profile
	resp, err := client.GetAnalyticsID("profile", "profile", constants.Username)
	if err != nil {
		klog.Warningf("Failed to get analytics id, %v", err)
	} else {
		r, err := analytics.GetAnalyticsScript(zone, resp.ID)
		if err != nil {
			klog.Warningf("Failed to get analytics script, %v", err)
		} else {
			profile.AnalyticsScript = r
			profile.EnableAnalytics = true
		}
	}

	formatDomain := func(appLocalDomainName string, customPrefixDomain string) []string {
		var r []string
		r = append(r, appLocalDomainName)

		if customPrefixDomain != "" {
			extAppHostName := fmt.Sprintf("%s.%s", customPrefixDomain, zone)
			extAppLocalName := fmt.Sprintf("%s.local.%s", customPrefixDomain, zone)

			if isEphemeral {
				extAppHostName = fmt.Sprintf("%s-%s.%s", customPrefixDomain, constants.Username, zone)
				extAppLocalName = fmt.Sprintf("%s-%s.local.%s", customPrefixDomain, constants.Username, zone)
			}

			r = append(r, extAppHostName, extAppLocalName)
		}
		return r
	}

	servers = append(servers, profile)

	// add apps servers
	for _, app := range r.apps {
		if app.Spec.Entrances == nil || len(app.Spec.Entrances) == 0 {
			continue
		}

		entrancecounts := len(app.Spec.Entrances)
		for index, entrance := range app.Spec.Entrances {
			if entrance.Host == "" {
				continue
			}
			prefix := getAppEntrancesHostName(entrancecounts, index, app.Spec.Name)
			customPrefixDomainName := ""

			customDomainEntrancesMap, err := getSettingsMap(&app, constants.ApplicationCustomDomain)
			if err != nil {
				klog.Warningf("failed to unmarshal application custom domain, %q, %s, %s, %v", prefix, app.Spec.Name, app.Spec.Appid, err)
			}

			customDomainEntranceMap, ok := customDomainEntrancesMap[entrance.Name]

			if app.Spec.Appid != "" && !app.Spec.IsSysApp { // third-party application
				prefix = getAppEntrancesHostName(entrancecounts, index, app.Spec.Appid)
				if ok {
					if customDomainEntranceMap != nil {
						customPrefixDomainName = customDomainEntranceMap[constants.ApplicationThirdLevelDomain]
					}
				}
			}
			klog.Infof("add domain server, app prefix: %q, %s", prefix, utils.ToJSON(app))

			appHostname := fmt.Sprintf("%s.%s", prefix, zone)
			appLocalName := fmt.Sprintf("%s.local.%s", prefix, zone)
			if isEphemeral {
				appHostname = fmt.Sprintf("%s-%s.%s", prefix, constants.Username, zone)
				appLocalName = fmt.Sprintf("%s-%s.local.%s", prefix, constants.Username, zone)
			}

			var enableAnalytics bool
			var analyticsScript string

			if app.Spec.Settings != nil {
				if v, ok := app.Spec.Settings["analyticsEnabled"]; ok && v == "true" {
					resp, err := client.GetAnalyticsID(app.Spec.Name, app.Spec.Appid, constants.Username)
					if err != nil {
						klog.Warningf("Failed to get analytics id, %v", err)
					} else {
						r, err := analytics.GetAnalyticsScript(zone, resp.ID)
						if err != nil {
							klog.Warningf("Failed to get analytics script, %v", err)
						} else {
							analyticsScript = r
							enableAnalytics = true
						}
					}
				}
			}

			_, enableOIDC := app.Spec.Settings["oidc.client.id"]

			s := config.Server{
				Hostname:   appHostname,
				Aliases:    formatDomain(appLocalName, customPrefixDomainName),
				EnableSSL:  true,
				EnableAuth: true,
				Locations: []config.Location{
					{
						Prefix:    "/",
						ProxyPass: fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", entrance.Host, app.Spec.Namespace, entrance.Port),
					},
				},
				EnableAnalytics:       enableAnalytics,
				AnalyticsScript:       analyticsScript,
				EnableOIDC:            enableOIDC,
				EnableWindowPushState: entrance.WindowPushState,
				Language:              language,
			}
			servers = append(servers, s)
		}
	}

	// add non application servers
	_servers := r.genNonAppServers(zone, isEphemeral, language)

	if _servers != nil && len(_servers) > 0 {
		servers = append(servers, _servers...)
	}

	return servers
}
