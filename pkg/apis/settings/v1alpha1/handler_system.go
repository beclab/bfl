package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"time"

	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/app_service/v1"
	"bytetrade.io/web3os/bfl/pkg/client/clientset/v1alpha1"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils"

	"github.com/emicklei/go-restful/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

var (
	systemServices = []string{
		"sync",
		"backup",
	}
)

func (h *Handler) handleEnableService(req *restful.Request, resp *restful.Response) {
	service := req.PathParameter(ParamServiceName)
	if !utils.ListContains(systemServices, service) {
		response.HandleNotFound(resp, errors.New("unknown service"))
		return
	}

	// fetch token from request
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)

	res, err := h.appServiceClient.EnableSystemService(service, token)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	code, ok := res["code"]
	if !ok || int(code.(float64)) != 200 {
		response.HandleInternalError(resp, errors.New("invoke app-service to enable service error"))
		return
	}

	k8sClient := runtime.NewKubeClient(req)
	go h.waitToNotify(service, ServiceEnabled, k8sClient)

	response.SuccessNoData(resp)
}

func (h *Handler) handleDisableService(req *restful.Request, resp *restful.Response) {
	service := req.PathParameter(ParamServiceName)
	if !utils.ListContains(systemServices, service) {
		response.HandleNotFound(resp, errors.New("unknown service"))
		return
	}

	// fetch token from request
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)

	res, err := h.appServiceClient.DisableSystemService(service, token)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	code, ok := res["code"]
	if !ok || int(code.(float64)) != 200 {
		response.HandleInternalError(resp, errors.New("invoke app-service to disable service error"))
		return
	}

	k8sClient := runtime.NewKubeClient(req)
	go h.waitToNotify(service, ServiceDisabled, k8sClient)

	response.SuccessNoData(resp)
}

func (h *Handler) handleGetServicesStatus(req *restful.Request, resp *restful.Response) {
	var res ResponseServices
	k8sClient := runtime.NewKubeClient(req)
	for _, s := range systemServices {
		status, url, err := h.getServiceStatus(req, k8sClient, s)
		if err != nil {
			klog.Error("get service status error, ", s, err)
			response.HandleError(resp, err)
			return
		}

		res.Services = append(res.Services, ServiceStatus{
			Name:   s,
			Status: status,
			URL:    url,
		})
	}

	response.Success(resp, res)
}

// return service status, service url, error
func (h *Handler) getServiceStatus(req *restful.Request, k8sClient v1alpha1.Client, service string) (string, string, error) {
	ns := fmt.Sprintf(constants.UserspaceNameFormat, constants.Username)

	ctx := req.Request.Context()
	pods, err := k8sClient.Kubernetes().CoreV1().Pods(ns).List(ctx,
		metav1.ListOptions{LabelSelector: "tier=" + service})
	if err != nil {
		return "", "", err
	}

	if len(pods.Items) == 0 {
		return ServiceDisabled, "", nil
	}

	if pods.Items[0].Status.Phase == corev1.PodRunning {
		url, err := h.getServiceUrl(req, constants.Username, service)
		if err != nil {
			klog.Error("get service url error, ", constants.Username, service, err)
			return "", "", err
		}
		return ServiceEnabled, url, nil
	}

	return ServiceDisabled, "", nil
}

func (h *Handler) getServiceUrl(req *restful.Request, user, serviceName string) (string, error) {
	appURL, err := app_service.AppUrlGenerator(req, user)
	if err != nil {
		return "", err
	}

	return appURL(serviceName, serviceName), nil
}

func (h *Handler) waitToNotify(service, watchStatus string, k8sClient v1alpha1.Client) {
	ns := fmt.Sprintf(constants.UserspaceNameFormat, constants.Username)

	ticker := time.NewTicker(2 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)

	defer func() {
		ticker.Stop()
		cancel()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pods, err := k8sClient.Kubernetes().CoreV1().Pods(ns).List(ctx,
				metav1.ListOptions{LabelSelector: "tier=" + service})
			if err != nil {
				klog.Error("wait service status error, ", err)
				continue
			}

			podStatus := ServiceDisabled
			if pods.Items[0].Status.Phase == corev1.PodRunning {
				podStatus = ServiceEnabled
			}

			if podStatus == watchStatus {
				if err := h.eventClient.CreateEvent("settings-event",
					fmt.Sprintf("service %s's status is changed", service),
					map[string]string{
						"service": service,
						"status":  watchStatus,
					},
				); err != nil {
					klog.Error("send event (service status change) to desktop error,", err)
				} else {
					return
				}
			}
		}
	}

}
