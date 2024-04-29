package v1alpha1

import (
	"sync"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	kubesphere "kubesphere.io/kubesphere/pkg/client/clientset/versioned"
	ctrl "sigs.k8s.io/controller-runtime"
)

// KubeClient global singleton client for kubernetes and kubesphere
var KubeClient Client

var syncOnce sync.Once

type Client interface {
	Kubernetes() kubernetes.Interface

	KubeSphere() kubesphere.Interface

	Config() *rest.Config
}

type kubeClient struct {
	// kubernetes client
	k8s kubernetes.Interface

	// kubeSphere client
	ks kubesphere.Interface

	// +optional
	master string

	config *rest.Config
}

func init() {
	syncOnce.Do(func() {
		client, err := NewKubeClient(nil)
		if err != nil {
			panic(err)
		}

		KubeClient = client
	})
}

// NewKubeClientOrDie creates a KubernetesClient and panic if there is an error
func NewKubeClientOrDie(kubeconfig string, config *rest.Config) Client {
	var err error

	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			panic(err)
		}
	}

	k := kubeClient{
		k8s:    kubernetes.NewForConfigOrDie(config),
		ks:     kubesphere.NewForConfigOrDie(config),
		master: config.Host,
		config: config,
	}
	return &k
}

// NewKubeClient creates a Kubernetes and kubesphere client
func NewKubeClient(config *rest.Config) (Client, error) {
	var err error

	if config == nil {
		config, err = ctrl.GetConfig()
		if err != nil {
			return nil, err
		}
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	ksClient, err := kubesphere.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	client := kubeClient{
		k8s:    k8sClient,
		ks:     ksClient,
		master: config.Host,
		config: config,
	}

	return &client, nil
}

func (k *kubeClient) Kubernetes() kubernetes.Interface {
	return k.k8s
}

func (k *kubeClient) KubeSphere() kubesphere.Interface {
	return k.ks
}

func (k *kubeClient) Config() *rest.Config {
	return k.config
}
