package v1alpha1

//
//import (
//	"encoding/json"
//	"errors"
//	"fmt"
//	"k8s.io/api/autoscaling/v2beta2"
//	"net/http"
//
//	"bytetrade.io/web3os/bfl/pkg/api/response"
//	"bytetrade.io/web3os/bfl/pkg/constants"
//
//	"github.com/emicklei/go-restful/v3"
//	"github.com/go-resty/resty/v2"
//	corev1 "k8s.io/api/core/v1"
//	k8serrs "k8s.io/apimachinery/pkg/api/errors"
//	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
//	k8sruntime "k8s.io/apimachinery/pkg/runtime"
//	"k8s.io/klog"
//	//"kubesphere.io/api/notification/v2beta1"
//	//"kubesphere.io/api/notification/v2beta2"
//)
//
//const (
//	Secret                      = "secrets"
//	NotificationEmailSecretKey  = "authPassword"
//	NotificationSecretNamespace = "kubesphere-monitoring-federated"
//)
//
////type notificationVerifyReq struct {
////	Config   v2beta2.Config   `json:"config"`
////	Receiver v2beta2.Receiver `json:"receiver"`
////}
//
////type NotificationSetting struct {
////	Config   v2beta2.ConfigSpec   `json:"config"`
////	Receiver v2beta2.ReceiverSpec `json:"receiver"`
////}
//
//func (h *Handler) applyNotificationConfig(req *restful.Request, resp *restful.Response) {
//	//token := req.Request.Header.Get(constants.AuthorizationTokenKey)
//	//
//	//var notification NotificationSetting
//	//err := req.ReadEntity(&notification)
//	//if err != nil {
//	//	response.HandleError(resp, err)
//	//	return
//	//}
//	//
//	//// save secret
//	//ntype, err := GetNotifyType(&notification.Config)
//	//if err != nil {
//	//	response.HandleError(resp, err)
//	//	return
//	//}
//	//err = h.applySecretForResource(token, ntype, &notification)
//	//if err != nil {
//	//	response.HandleError(resp, err)
//	//	return
//	//}
//	//
//	//configName, err := GetObjectName(v2beta2.ResourcesPluralConfig, ntype)
//	//if err != nil {
//	//	response.HandleError(resp, err)
//	//	return
//	//}
//	//
//	//config := v2beta2.Config{
//	//	ObjectMeta: metav1.ObjectMeta{
//	//		Name: configName,
//	//		Labels: map[string]string{
//	//			"channel": ntype,
//	//		},
//	//	},
//	//	Spec: notification.Config,
//	//}
//	//// kubesphere v3.3.0 just provides v2beta1 api
//	//klog.Info("v2beta2 config to v2beta1")
//	//v2beta1config := v2beta1.Config{}
//	//config.ConvertTo(&v2beta1config)
//	//
//	//err = h.applyResource(token, v2beta2.ResourcesPluralConfig, ntype, &v2beta1config)
//	//if err != nil {
//	//	response.HandleError(resp, err)
//	//	return
//	//}
//	//
//	//AddConfigSelector(ntype, &notification)
//	//receiverName, err := GetObjectName(v2beta2.ResourcesPluralReceiver, ntype)
//	//if err != nil {
//	//	response.HandleError(resp, err)
//	//	return
//	//}
//	//
//	//receiver := v2beta2.Receiver{
//	//	ObjectMeta: metav1.ObjectMeta{
//	//		Name: receiverName,
//	//	},
//	//	Spec: notification.Receiver,
//	//}
//	//
//	//err = h.applyResource(token, v2beta2.ResourcesPluralReceiver, ntype, &receiver)
//	//if err != nil {
//	//	response.HandleError(resp, err)
//	//	return
//	//}
//
//	response.SuccessNoData(resp)
//}
//
//func (h *Handler) getNotificationConfig(req *restful.Request, resp *restful.Response) {
//	//	token := req.Request.Header.Get(constants.AuthorizationTokenKey)
//	//	ntype := req.QueryParameter("type")
//	//
//	//	if ntype == "" {
//	//		response.HandleError(resp, errors.New("the type parameter not found"))
//	//		return
//	//	}
//	//
//	//	receiver, err := h.getResource(token, v2beta2.ResourcesPluralReceiver, ntype)
//	//	if err != nil {
//	//		response.HandleError(resp, err)
//	//		return
//	//	}
//	//
//	//	config, err := h.getResource(token, v2beta2.ResourcesPluralConfig, ntype)
//	//	if err != nil {
//	//		response.HandleError(resp, err)
//	//		return
//	//	}
//	//
//	//	secret, err := h.getResource(token, Secret, ntype)
//	//	if err != nil {
//	//		response.HandleError(resp, err)
//	//		return
//	//	}
//	//
//	//	// kubesphere v3.3.0 just provides v2beta1 api
//	//	klog.Info("v2beta1 config to v2beta2")
//	//	v2config := v2beta2.Config{}
//	//	v2config.ConvertFrom(config.(*v2beta1.Config))
//	//
//	//	AddConfigSecretValue(ntype, secret.(*corev1.Secret), &v2config)
//	//
//	//	notification := NotificationSetting{
//	//		Config:   v2config.Spec,
//	//		Receiver: receiver.(*v2beta2.Receiver).Spec,
//	//	}
//	//
//	//	response.Success(resp, notification)
//	//}
//	//
//	//func (h *Handler) deleteNotificationConfig(req *restful.Request, resp *restful.Response) {
//	//	token := req.Request.Header.Get(constants.AuthorizationTokenKey)
//	//	ntype := req.QueryParameter("type")
//	//	if ntype == "" {
//	//		response.HandleError(resp, errors.New("the type parameter not found"))
//	//		return
//	//	}
//	//	err := h.deleteResource(token, v2beta2.ResourcesPluralReceiver, ntype)
//	//	if err != nil {
//	//		response.HandleError(resp, err)
//	//		return
//	//	}
//	//
//	//	err = h.deleteResource(token, v2beta2.ResourcesPluralConfig, ntype)
//	//	if err != nil {
//	//		response.HandleError(resp, err)
//	//		return
//	//	}
//	//
//	//	err = h.deleteResource(token, Secret, ntype)
//	//	if err != nil {
//	//		response.HandleError(resp, err)
//	//		return
//	//	}
//
//	response.SuccessNoData(resp)
//}
//
//func (h *Handler) verifyNotificationConfig(req *restful.Request, resp *restful.Response) {
//	//token := req.Request.Header.Get(constants.AuthorizationTokenKey)
//	//
//	//var notification NotificationSetting
//	//err := req.ReadEntity(&notification)
//	//if err != nil {
//	//	response.HandleError(resp, err)
//	//	return
//	//}
//	//
//	//notifyReq := notificationVerifyReq{
//	//	Config: v2beta2.Config{
//	//		ObjectMeta: metav1.ObjectMeta{
//	//			Name: "test-config",
//	//			Labels: map[string]string{
//	//				"type": "tenant",
//	//				"user": constants.Username,
//	//				"app":  "notification-manager",
//	//			},
//	//		},
//	//		Spec: notification.Config,
//	//	},
//	//	Receiver: v2beta2.Receiver{
//	//		ObjectMeta: metav1.ObjectMeta{
//	//			Name: "test-receiver",
//	//			Labels: map[string]string{
//	//				"type": "tenant",
//	//				"user": constants.Username,
//	//				"app":  "notification-manager",
//	//			},
//	//		},
//	//		Spec: notification.Receiver,
//	//	},
//	//}
//	//url := fmt.Sprintf("http://%s/kapis/notification.kubesphere.io/v2beta2/configs/notification/users/%s/verification",
//	//	constants.KubeSphereAPIHost,
//	//	constants.Username,
//	//)
//	//
//	//klog.Info("request url: ", url)
//	//
//	//r, err := h.httpClient.R().
//	//	SetHeaders(map[string]string{
//	//		restful.HEADER_ContentType: restful.MIME_JSON,
//	//		restful.HEADER_Accept:      restful.MIME_JSON,
//	//		"Authorization":            "Bearer " + token,
//	//	}).
//	//	SetBody(notifyReq).
//	//	Post(url)
//	//
//	//if err != nil {
//	//	response.HandleError(resp, err)
//	//	return
//	//}
//	//
//	//if r.StatusCode() != http.StatusOK {
//	//	response.HandleError(resp, errors.New(string(r.Body())))
//	//	return
//	//}
//
//	response.SuccessNoData(resp)
//}
//
//func (h *Handler) applyResource(token, resource, notifyType string, newObj k8sruntime.Object) error {
//	oldObj, err := h.getResource(token, resource, notifyType)
//	if err != nil && !k8serrs.IsNotFound(err) {
//		return err
//	}
//
//	if oldObj == nil {
//		req := h.notificationResourceRequest(resty.MethodPost, token, resource, "") // POST, name is unnecerssary
//
//		resp, err := req.SetBody(newObj).Send()
//		if err != nil {
//			return err
//		}
//
//		if resp.StatusCode() != http.StatusOK {
//			return errors.New(string(resp.Body()))
//		}
//	} else {
//		name, err := GetObjectName(resource, notifyType)
//		if err != nil {
//			return err
//		}
//
//		newObj = CopyObject(resource, oldObj, newObj)
//		req := h.notificationResourceRequest(resty.MethodPut, token, resource, name)
//
//		resp, err := req.SetBody(newObj).Send()
//		if err != nil {
//			return err
//		}
//
//		if resp.StatusCode() != http.StatusOK {
//			return errors.New(string(resp.Body()))
//		}
//	}
//	return nil
//}
//
//func (h *Handler) getResource(token, resource, notifyType string) (k8sruntime.Object, error) {
//	name, err := GetObjectName(resource, notifyType)
//	if err != nil {
//		return nil, err
//	}
//
//	req := h.notificationResourceRequest(resty.MethodGet, token, resource, name)
//
//	resp, err := req.Send()
//
//	if err != nil {
//		return nil, err
//	}
//
//	if resp.StatusCode() != http.StatusOK {
//		if resp.StatusCode() == http.StatusNotFound {
//			return nil, k8serrs.NewNotFound(v2beta2.Resource(resource), name)
//		}
//		return nil, fmt.Errorf("get notification resource %s error, %s", resource, string(resp.Body()))
//	}
//
//	ret := GetObject(resource)
//	if ret == nil {
//		return nil, errors.New("unknown resource")
//	}
//
//	err = json.Unmarshal(resp.Body(), ret)
//	if err != nil {
//		return nil, err
//	}
//
//	return ret, nil
//}
//
//func (h *Handler) deleteResource(token, resource, notifyType string) error {
//	name, err := GetObjectName(resource, notifyType)
//	if err != nil {
//		return err
//	}
//
//	req := h.notificationResourceRequest(resty.MethodDelete, token, resource, name)
//
//	resp, err := req.Send()
//
//	if err != nil {
//		return err
//	}
//
//	if resp.StatusCode() != http.StatusOK {
//		if resp.StatusCode() == http.StatusNotFound {
//			return k8serrs.NewNotFound(v2beta2.Resource(resource), name)
//		}
//		return fmt.Errorf("delete notification resource %s error, %s", resource, string(resp.Body()))
//	}
//
//	return nil
//}
//
//func (h *Handler) notificationResourceRequest(method, token, resource, name string) *resty.Request {
//	nameParam := ""
//	if name != "" {
//		nameParam = "/" + name
//	}
//	url := fmt.Sprintf("http://%s/kapis/notification.kubesphere.io/v2beta1/users/%s/%s%s",
//		constants.KubeSphereAPIHost,
//		constants.Username,
//		resource,
//		nameParam,
//	)
//
//	klog.Info("request url: ", url)
//
//	r := h.httpClient.R().
//		SetHeaders(map[string]string{
//			restful.HEADER_ContentType: restful.MIME_JSON,
//			restful.HEADER_Accept:      restful.MIME_JSON,
//			"Authorization":            "Bearer " + token,
//		})
//
//	r.Method = method
//	r.URL = url
//
//	return r
//}
//
//func (h *Handler) applySecretForResource(token, ntype string, notification *NotificationSetting) error {
//	switch ntype {
//	case "email":
//		secretName, err := GetObjectName(Secret, ntype)
//		if err != nil {
//			return err
//		}
//		password := notification.Config.Email.AuthPassword.Value
//		secret := corev1.Secret{
//			ObjectMeta: metav1.ObjectMeta{
//				Name:      secretName,
//				Namespace: NotificationSecretNamespace,
//			},
//			Type: corev1.SecretTypeOpaque,
//			Data: map[string][]byte{
//				NotificationEmailSecretKey: []byte(password),
//			},
//		}
//
//		err = h.applyResource(token, Secret, ntype, &secret)
//		if err != nil {
//			return err
//		}
//
//		notification.Config.Email.AuthPassword.ValueFrom = &v2beta2.ValueSource{
//			SecretKeyRef: &v2beta2.SecretKeySelector{
//				Key:       NotificationEmailSecretKey,
//				Name:      secretName,
//				Namespace: NotificationSecretNamespace,
//			},
//		}
//
//	default:
//		return errors.New("not supported")
//	}
//
//	return nil
//}
//
//func AddConfigSecretValue(ntype string, secret *corev1.Secret, config *v2beta2.Config) {
//	switch ntype {
//	case "email":
//		value := secret.Data[NotificationEmailSecretKey]
//		config.Spec.Email.AuthPassword.Value = string(value)
//	}
//}
//
//func AddConfigSelector(ntype string, setting *NotificationSetting) {
//	selector := &metav1.LabelSelector{
//		MatchLabels: map[string]string{
//			"user":    constants.Username,
//			"channel": ntype,
//		},
//	}
//
//	switch ntype {
//	case "email":
//		setting.Receiver.Email.EmailConfigSelector = selector
//		*setting.Receiver.Email.Enabled = true
//	case "dingtalk":
//		setting.Receiver.DingTalk.DingTalkConfigSelector = selector
//		*setting.Receiver.DingTalk.Enabled = true
//
//	default:
//	}
//}
//
//func GetObject(resource string) k8sruntime.Object {
//
//	switch resource {
//	case v2beta2.ResourcesPluralConfig:
//		return &v2beta1.Config{TypeMeta: metav1.TypeMeta{APIVersion: "notification.kubesphere.io/v2beta1"}}
//	case v2beta2.ResourcesPluralReceiver:
//		return &v2beta2.Receiver{TypeMeta: metav1.TypeMeta{APIVersion: "notification.kubesphere.io/v2beta2"}}
//	case Secret:
//		return &corev1.Secret{}
//	default:
//		return nil
//	}
//}
//
//func CopyObject(resource string, oldObj, newObj k8sruntime.Object) k8sruntime.Object {
//
//	switch resource {
//	case v2beta2.ResourcesPluralConfig:
//		newConfig := newObj.(*v2beta1.Config)
//		oldConfig := oldObj.(*v2beta1.Config)
//		newConfig.ObjectMeta = oldConfig.ObjectMeta
//		return newConfig
//	case v2beta2.ResourcesPluralReceiver:
//		newReceiver := newObj.(*v2beta2.Receiver)
//		oldReceiver := oldObj.(*v2beta2.Receiver)
//		newReceiver.ObjectMeta = oldReceiver.ObjectMeta
//	case Secret:
//		newSecret := newObj.(*corev1.Secret)
//		oldSecret := oldObj.(*corev1.Secret)
//		newSecret.ObjectMeta = oldSecret.ObjectMeta
//	default:
//		return nil
//	}
//
//	return newObj
//}
//
//func GetObjectName(resource, ntype string) (string, error) {
//	switch resource {
//	case v2beta2.ResourcesPluralConfig:
//		return constants.Username + "-" + ntype + "-config", nil
//	case v2beta2.ResourcesPluralReceiver:
//		return constants.Username + "-" + ntype + "-receiver", nil
//	case Secret:
//		return constants.Username + "-" + ntype + "-config-secret", nil
//	default:
//		return "", errors.New("unknown resource type")
//	}
//
//}
//
//func GetNotifyType(config *v2beta2.ConfigSpec) (string, error) {
//	if config.Email != nil {
//		return "email", nil
//	}
//
//	if config.DingTalk != nil {
//		return "dingtalk", nil
//	}
//	// if config.Feishu != nil {
//	// 	return "feishu", nil
//	// }
//	if config.Slack != nil {
//		return "slack", nil
//	}
//	if config.Sms != nil {
//		return "sms", nil
//	}
//	if config.Wechat != nil {
//		return "wechat", nil
//	}
//	if config.Webhook != nil {
//		// TODO: subtype - apn,websocket
//		return "webhook", nil
//	}
//
//	return "", errors.New("unknown notification channel type")
//}
