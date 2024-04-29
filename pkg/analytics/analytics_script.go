package analytics

import (
	"bytes"
	"text/template"
)

const analyticsScript = "<script async crossorigin='anonymous' src='https://dashboard.{{ .Zone }}/js/script.js' data-website-id='{{ .DataWebsiteID }}'></script>"

func GetAnalyticsScript(zone string, dataWebsiteID string) (string, error) {
	tpl, err := template.New("analyticsScript").Parse(analyticsScript)
	if err != nil {
		return "", err
	}
	var analyticsScript bytes.Buffer
	data := struct {
		Zone          string
		DataWebsiteID string
	}{
		Zone:          zone,
		DataWebsiteID: dataWebsiteID,
	}
	err = tpl.Execute(&analyticsScript, data)
	if err != nil {
		return "", err
	}
	return analyticsScript.String(), nil
}
