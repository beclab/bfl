package v1alpha1

import (
	"fmt"

	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"github.com/emicklei/go-restful/v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	"k8s.io/klog/v2"
)

type AclState string

const (
	AclStateApplying AclState = "applying"
	AclStateApplied  AclState = "applied"

	ENV_HEADSCALE_ACL_SSH = "HEADSCALE_ACL_SSH"
)

type Acl struct {
	AllowSSH bool     `json:"allow_ssh"`
	State    AclState `json:"state"`
}

func (h *Handler) handleGetHeadscaleSshAcl(req *restful.Request, resp *restful.Response) {

	k8sClient := runtime.NewKubeClient(req)

	// get headscale pods, check if headscale is running, if not, return "acl applying"
	// and if headscale is running, check if the acl env from headscale deployment, then return the acl
	namespace := fmt.Sprintf("user-space-%s", constants.Username)
	pods, err := k8sClient.Kubernetes().CoreV1().Pods(namespace).
		List(req.Request.Context(), metav1.ListOptions{LabelSelector: "app=headscale"})
	if err != nil {
		if apierrors.IsNotFound(err) {
			response.Success(resp, Acl{State: AclStateApplying})
			return
		}

		klog.Error("Failed to get headscale pods: ", err)
		response.HandleError(resp, err)
		return
	}

	if len(pods.Items) == 0 {
		response.Success(resp, Acl{State: AclStateApplying})
		return
	}

	if pods.Items[0].Status.Phase != "Running" {
		response.Success(resp, Acl{State: AclStateApplying})
		return
	}

	// get headscale deployment
	deploy, err := k8sClient.Kubernetes().AppsV1().Deployments(namespace).
		Get(req.Request.Context(), "headscale", metav1.GetOptions{})

	if err != nil {
		klog.Error("Failed to get headscale deployment: ", err)
		response.HandleError(resp, err)
		return
	}

	// get headscale acl env
	allowSSH := false
	for _, env := range deploy.Spec.Template.Spec.Containers[0].Env {
		if env.Name == ENV_HEADSCALE_ACL_SSH {
			allowSSH = env.Value == "true"
			break
		}
	}

	response.Success(resp, Acl{AllowSSH: allowSSH, State: AclStateApplied})
}

func (h *Handler) handleDisableHeadscaleSshAcl(req *restful.Request, resp *restful.Response) {
	h.setHeadscaleSshAcl(req, resp, "false")
}

func (h *Handler) handleEnableHeadscaleSshAcl(req *restful.Request, resp *restful.Response) {
	h.setHeadscaleSshAcl(req, resp, "true")
}

func (h *Handler) setHeadscaleSshAcl(req *restful.Request, resp *restful.Response, value string) {
	k8sClient := runtime.NewKubeClient(req)
	namespace := fmt.Sprintf("user-space-%s", constants.Username)

	// get headscale deployment
	deploy, err := k8sClient.Kubernetes().AppsV1().Deployments(namespace).
		Get(req.Request.Context(), "headscale", metav1.GetOptions{})

	if err != nil {
		klog.Error("Failed to get headscale deployment: ", err)
		response.HandleError(resp, err)
		return
	}

	// update headscale deployment
	found := false
	for i, env := range deploy.Spec.Template.Spec.Containers[0].Env {
		if env.Name == ENV_HEADSCALE_ACL_SSH {
			deploy.Spec.Template.Spec.Containers[0].Env[i].Value = value
			found = true
			break
		}
	}

	if !found {
		deploy.Spec.Template.Spec.Containers[0].Env = append(deploy.Spec.Template.Spec.Containers[0].Env,
			corev1.EnvVar{Name: ENV_HEADSCALE_ACL_SSH, Value: value})
	}

	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		_, err = k8sClient.Kubernetes().AppsV1().Deployments(namespace).
			Update(req.Request.Context(), deploy, metav1.UpdateOptions{})
		return err
	})

	if err != nil {
		klog.Error("Failed to update headscale deployment: ", err)
		response.HandleError(resp, err)
		return
	}

	response.SuccessNoData(resp)
}
