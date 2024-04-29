package v1alpha1

import (
	"encoding/json"
	"testing"

	"k8s.io/klog/v2"
)

func TestRawMsg(t *testing.T) {
	data := make(map[string]interface{})
	data["value"] = map[string]interface{}{
		"test": "sadasdsa",
		"int":  1,
	}

	body, _ := json.Marshal(data)

	value, err := json.Marshal(json.RawMessage(body))
	if err != nil {
		klog.Error(err)
		t.Fail()
		return
	}

	klog.Info(body)
	klog.Info(value)
}
