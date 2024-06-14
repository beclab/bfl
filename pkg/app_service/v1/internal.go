package app_service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"bytetrade.io/web3os/bfl/pkg/constants"

	"k8s.io/klog/v2"
)

func (c *Client) fetchAppInfoFromAppService(appname, token string) (map[string]interface{}, error) {
	appServiceHost := os.Getenv(AppServiceHostEnv)
	appServicePort := os.Getenv(AppServicePortEnv)
	urlStr := fmt.Sprintf(AppServiceGetURLTempl, appServiceHost, appServicePort, appname)

	return c.doHttpGetOne(urlStr, token)
}

func (c *Client) getAppInfoFromData(data map[string]interface{}) (*AppInfo, error) {
	appSpec, ok := data["spec"].(map[string]interface{})
	if !ok {
		klog.Error("get app info error: ", data)
		return nil, errors.New("app info is invalid")
	}

	return &AppInfo{
		ID:             genAppID(appSpec),
		Name:           appSpec["name"].(string),
		Namespace:      appSpec["namespace"].(string),
		DeploymentName: appSpec["deployment"].(string),
		Owner:          appSpec["owner"].(string)}, nil
}

func (c *Client) getAppListFromData(apps []map[string]interface{}) ([]*AppInfo, error) {

	var res []*AppInfo
	for _, data := range apps {
		var appEntrances []Entrance
		appSpec, ok := data["spec"].(map[string]interface{})
		if !ok {
			klog.Error("get app info error: ", data)
			return nil, errors.New("app info is invalid")
		}

		isSysApp := appSpec["isSysApp"].(bool)

		// get app settings to filter system service not to list
		title, target, state := "", "", ""
		isClusterScoped, mobileSupported := false, false
		settings, ok := appSpec["settings"]
		if ok {
			settingsMap := settings.(map[string]interface{})
			_, ok = settingsMap["system_service"]
			if ok {
				// It is the system service, not app
				continue
			} // end ok

			if t, ok := settingsMap["title"]; ok {
				title = t.(string)
			}
			if t, ok := settingsMap["clusterScoped"]; ok && t == "true" {
				isClusterScoped = true
			}

			if t, ok := settingsMap["target"]; ok {
				target = t.(string)
			}
			if t, ok := settingsMap["mobileSupported"]; ok && t == "true" {
				mobileSupported = true
			}
		}

		status, ok := data["status"].(map[string]interface{})
		if ok {
			if t, ok := status["state"]; ok {
				state = t.(string)
			}
		}

		entrances, ok := appSpec["entrances"]
		if ok {
			entrancesInterface := entrances.([]interface{})
			for _, entranceInterface := range entrancesInterface {
				entranceMap := entranceInterface.(map[string]interface{})
				var appEntrance Entrance
				if t, ok := entranceMap["name"]; ok {
					appEntrance.Name = stringOrEmpty(t)
				}

				if t, ok := entranceMap["title"]; ok {
					appEntrance.Title = stringOrEmpty(t)
				}

				if t, ok := entranceMap["icon"]; ok {
					appEntrance.Icon = stringOrEmpty(t)
				}
				if t, ok := entranceMap["invisible"]; ok && t.(bool) == true {
					appEntrance.Invisible = true
				}
				if t, ok := entranceMap["authLevel"]; ok {
					appEntrance.AuthLevel = stringOrEmpty(t)
				}
				if t, ok := entranceMap["openMethod"]; ok {
					appEntrance.OpenMethod = stringOrEmpty(t)
				} else {
					appEntrance.OpenMethod = "default"
				}
				appEntrances = append(appEntrances, appEntrance)
			}
		}

		res = append(res, &AppInfo{
			ID:              genAppID(appSpec),
			Name:            stringOrEmpty(appSpec["name"]),
			Namespace:       stringOrEmpty(appSpec["namespace"]),
			DeploymentName:  stringOrEmpty(appSpec["deployment"]),
			Owner:           stringOrEmpty(appSpec["owner"]),
			Icon:            stringOrEmpty(appSpec["icon"]),
			Title:           title,
			Target:          target,
			Entrances:       appEntrances,
			State:           state,
			IsSysApp:        isSysApp,
			IsClusterScoped: isClusterScoped,
			MobileSupported: mobileSupported,
		})

	}

	return res, nil

}

func (c *Client) doHttpGetResponse(urlStr, token string) (*http.Response, error) {
	url, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodGet,
		Header: http.Header{
			constants.AuthorizationTokenKey: []string{token},
		},
		URL: url,
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		klog.Error("do request error: ", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		klog.Error("response not ok, ", resp.Status)
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		return nil, fmt.Errorf("response error, code %d, msg: %s", resp.StatusCode, string(data))
	}

	return resp, nil
}

func (c *Client) readHttpResponse(resp *http.Response) (map[string]interface{}, error) {
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	app := make(map[string]interface{}) // simple get. TODO: application struct
	err = json.Unmarshal(data, &app)
	if err != nil {
		klog.Error("parse response error: ", err, string(data))
		return nil, err
	}

	return app, nil

}

func (c *Client) readHttpResponseList(resp *http.Response) ([]map[string]interface{}, error) {
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apps []map[string]interface{} // simple get. TODO: application struct
	err = json.Unmarshal(data, &apps)
	if err != nil {
		klog.Error("parse response error: ", err, string(data))
		return nil, err
	}

	return apps, nil
}

func (c *Client) doHttpGetOne(urlStr, token string) (map[string]interface{}, error) {
	resp, err := c.doHttpGetResponse(urlStr, token)
	if err != nil {
		return nil, err
	}

	return c.readHttpResponse(resp)
}

func (c *Client) doHttpGetList(urlStr, token string) ([]map[string]interface{}, error) {
	resp, err := c.doHttpGetResponse(urlStr, token)
	if err != nil {
		return nil, err
	}

	return c.readHttpResponseList(resp)
}

func (c *Client) doHttpPost(urlStr, token string, bodydata interface{}) (map[string]interface{}, error) {
	var data io.Reader
	if bodydata != nil {
		jsonData, err := json.Marshal(bodydata)
		if err != nil {
			return nil, errors.New("body data parse error")
		}

		data = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(http.MethodPost, urlStr, data)
	if err != nil {
		return nil, err
	}
	req.Header.Add(constants.AuthorizationTokenKey, token)
	req.Header.Add("content-type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		klog.Error("do request error: ", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		klog.Error("response not ok, ", resp.Status)
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		return nil, fmt.Errorf("response error, code %d, msg: %s", resp.StatusCode, string(data))
	}

	return c.readHttpResponse(resp)
}

func stringOrEmpty(value interface{}) string {
	if value == nil {
		return ""
	}

	return value.(string)
}

// TODO: get app listing id
func genAppID(appSpec map[string]interface{}) string {
	return appSpec["appid"].(string)
}
