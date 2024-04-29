package analytics

import (
	"testing"
)

func TestGetAnalyticsScript(t *testing.T) {
	zone := "bytetrade.snowinning.com"
	dataWebsiteID := "5e65085f-56bd-43f1-9461-3aa263a5561c"

	expectedScript := `<script async crossorigin='anonymous' src='https://analytics.bytetrade.snowinning.com/script.js' data-website-id='5e65085f-56bd-43f1-9461-3aa263a5561c'></script>`

	script, err := GetAnalyticsScript(zone, dataWebsiteID)
	if err != nil {
		t.Errorf("GetAnalyticsScript returned an error: %v", err)
	}

	if script != expectedScript {
		t.Errorf("Expected script:\n%s\n\nGot:\n%s", expectedScript, script)
	}
}
