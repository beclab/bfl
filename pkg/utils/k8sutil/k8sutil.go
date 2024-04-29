package k8sutil

import (
	"context"
	"net"
	"time"

	"bytetrade.io/web3os/bfl/internal/log"
	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/pointer"
)

func GetL4ProxyNodeIP(ctx context.Context, waitTimeout time.Duration) (*string, error) {
	return GetPodHostIPWithLabelSelector(ctx, waitTimeout, constants.L4ProxyNamespace, "app=l4-bfl-proxy")
}

func GetPodHostIPWithLabelSelector(ctx context.Context, waitTimeout time.Duration, namespace, labelSelector string) (*string, error) {
	kc, err := runtime.NewKubeClientInCluster()
	if err != nil {
		return nil, errors.Errorf("new kube client in cluster: %v", err)
	}

	var nodeIP *string
	var observations int32

	err = wait.PollImmediate(time.Second, waitTimeout, func() (bool, error) {
		var podList *corev1.PodList
		podList, err = kc.Kubernetes().CoreV1().Pods(namespace).List(ctx,
			metav1.ListOptions{LabelSelector: labelSelector})
		if err != nil && apierrors.IsNotFound(err) {
			return false, nil
		} else if err != nil {
			return false, errors.WithStack(err)
		}

		if podList != nil && len(podList.Items) > 0 {
			pod := podList.Items[0]
			if pod.Status.HostIP != "" {
				nodeIP = pointer.String(pod.Status.HostIP)
				observations++
			}
		}

		if observations > 2 {
			return true, nil
		}

		return false, nil
	})

	if err != nil {
		return nil, errors.WithStack(err)
	}

	return nodeIP, err
}

func GetMasterExternalIP(ctx context.Context) *string {
	kc, err := runtime.NewKubeClientInCluster()
	if err != nil {
		log.Warnf("new kube client: %v", err)
		return nil
	}

	users, err := kc.KubeSphere().IamV1alpha2().Users().
		List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Warnf("list users: %v", err)
		return nil
	}

	var externalIP string

	for _, user := range users.Items {
		if role, ok := user.Annotations[constants.UserAnnotationOwnerRole]; ok && role == constants.RolePlatformAdmin {
			ip, ok1 := user.Annotations[constants.UserAnnotationPublicDomainIp]
			if ok1 && ip != "" {
				if _ip := net.ParseIP(ip); _ip != nil {
					externalIP = ip
					break
				}
			}
		}
	}

	if externalIP == "" {
		externalIP = utils.GetMyExternalIPAddr()
	}

	return pointer.String(externalIP)
}
