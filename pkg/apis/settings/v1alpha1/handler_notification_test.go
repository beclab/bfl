package v1alpha1

//
//import (
//	"encoding/json"
//	"testing"
//
//	"bytetrade.io/web3os/bfl/pkg/constants"
//	"bytetrade.io/web3os/bfl/pkg/utils"
//
//	"kubesphere.io/api/notification/v2beta2"
//)
//
//func TestGetNodificationResource(t *testing.T) {
//	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzM4NjMzMjgsImlhdCI6MTY3Mzg1NjEyOCwiaXNzIjoia3ViZXNwaGVyZSIsInN1YiI6ImxpdXl1IiwidG9rZW5fdHlwZSI6ImFjY2Vzc190b2tlbiIsInVzZXJuYW1lIjoibGl1eXUiLCJleHRyYSI6eyJ1bmluaXRpYWxpemVkIjpbInRydWUiXX19.tz2VpBZE-YTh-t_1OGkDaz_xnhaHqZv-MR26-fm7fS4"
//	constants.KubeSphereAPIHost = "52.2.5.188:30335"
//	constants.Username = "liuyu"
//
//	h := New()
//
//	testConfig := `{
//		"apiVersion": "notification.kubesphere.io/v2beta2",
//		"kind": "Config",
//		"metadata": {
//			"name": "liuyu-email-config"
//		},
//		"spec": {
//			"email": {
//				"authPassword": {
//					"value": "lyu330221"
//				},
//				"authUsername": "liuyu@gmail.com",
//				"from": "liuyu@bytetrade.io",
//				"requireTLS": true,
//				"smartHost": {
//					"host": "smtp.gmail.com",
//					"port": 587
//				}
//			}
//		}
//	}`
//
//	var config v2beta2.Config
//	err := json.Unmarshal([]byte(testConfig), &config)
//	if err != nil {
//		t.Log(err)
//		t.FailNow()
//	}
//
//	err = h.applyResource(token, v2beta2.ResourcesPluralConfig, "email", &config)
//	if err != nil {
//		t.Log(err)
//		t.FailNow()
//	}
//
//	c, err := h.getResource(token, v2beta2.ResourcesPluralConfig, "email")
//	if err != nil {
//		t.Log(err)
//		t.FailNow()
//	}
//
//	t.Log(utils.PrettyJSON(c))
//
//	err = h.deleteResource(token, v2beta2.ResourcesPluralConfig, "email")
//	if err != nil {
//		t.Log(err)
//		t.FailNow()
//	}
//
//	t.Log("delete success")
//}
