package v1alpha1

import (
	"context"
	"fmt"

	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/app_service/v1"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"github.com/emicklei/go-restful/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	"k8s.io/klog/v2"
)

func (h *Handler) scalePatch(scaleTo int32, req *restful.Request, resp *restful.Response) error {

	appInfo, err := h.getAppInfo(req)
	if err != nil {
		// TODO: not-found to be responsed
		klog.Error("get app info err:", err)
		return err
	}

	deployments := runtime.NewKubeClient(req).Kubernetes().AppsV1().Deployments(appInfo.Namespace)
	appDeploy, err := h.getAppDeployment(req, appInfo, deployments)
	if err != nil {
		return err
	}

	// validate deployment of owner
	user := req.Attribute(constants.UserContextAttribute).(string)
	if appDeploy.AppInfo.Owner != user {
		return ErrOperationIllegal
	}

	replicas := appDeploy.Deployment.Spec.Replicas
	if (*replicas) == scaleTo {
		return nil
	}

	// launch or close apps via scaling replicas
	patch := fmt.Sprintf("{\"spec\":{\"replicas\":%d}}", scaleTo)

	// patch type ???
	if _, err := deployments.Patch(context.TODO(),
		appDeploy.AppInfo.DeploymentName,
		types.MergePatchType,
		[]byte(patch),
		metav1.PatchOptions{}); err != nil {

		return err
	}

	return nil
}

func (h *Handler) getAppInfo(req *restful.Request) (*app_service.AppInfo, error) {

	appName := req.PathParameter(ParamAppName)
	//appNamespace := req.PathParameter(ParamAppNamespace)
	token := req.Request.Header.Get(constants.AuthorizationTokenKey)
	return h.appService.GetAppInfo(appName, token)
}

func (h *Handler) getAppDeployment(req *restful.Request, appInfo *app_service.AppInfo, deploymentsClient appsv1.DeploymentInterface) (*app_service.AppDeploymentInfo, error) {

	// try to get deployment
	deployment, err := deploymentsClient.Get(req.Request.Context(), appInfo.DeploymentName, metav1.GetOptions{})
	if err != nil {
		klog.Errorf("Deployment {%s} in namespace {%s}", appInfo.DeploymentName, appInfo.Namespace)
		return nil, err
	}

	return &app_service.AppDeploymentInfo{AppInfo: appInfo, Deployment: deployment}, nil
}
