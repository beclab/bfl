package dynamic_client

import (
	"context"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

var syncOnce sync.Once

type ResourceDynamicClient struct {
	namespace string
	gvr       schema.GroupVersionResource
	c         dynamic.Interface
	informer  informers.GenericInformer
}

var resourceInformerFactory dynamicinformer.DynamicSharedInformerFactory
var clientCtx context.Context

func init() {
	syncOnce.Do(func() {
		config := ctrl.GetConfigOrDie()
		client := dynamic.NewForConfigOrDie(config)
		resourceInformerFactory = dynamicinformer.NewDynamicSharedInformerFactory(client, 0)
		clientCtx = context.Background()
	})
}

func NewResourceDynamicClient() (*ResourceDynamicClient, error) {
	config, err := ctrl.GetConfig()
	if err != nil {
		return nil, err
	}

	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &ResourceDynamicClient{c: client}, nil
}

func NewResourceDynamicClientOrDie() *ResourceDynamicClient {
	config, err := ctrl.GetConfig()
	if err != nil {
		panic(err)
	}

	client, err := dynamic.NewForConfig(config)
	if err != nil {
		panic(err)
	}
	return &ResourceDynamicClient{c: client}
}

func (r *ResourceDynamicClient) Namespace(ns string) *ResourceDynamicClient {
	r.namespace = ns
	return r
}

func (r *ResourceDynamicClient) GroupVersionResource(gvr schema.GroupVersionResource) *ResourceDynamicClient {
	r.gvr = gvr
	r.informer = resourceInformerFactory.ForResource(gvr)

	// add a new resource informer, start to sync cache
	// factory will not start syncing duplicately
	resourceInformerFactory.Start(clientCtx.Done())
	resourceInformerFactory.WaitForCacheSync(clientCtx.Done())

	return r
}

func (r *ResourceDynamicClient) unmarshal(v map[string]any, obj any) error {
	return UnstructuredConverter.FromUnstructured(v, obj)
}

func (r *ResourceDynamicClient) Delete(ctx context.Context, name string, options metav1.DeleteOptions) error {
	return r.c.Resource(r.gvr).Namespace(r.namespace).Delete(ctx, name, options)
}

func (r *ResourceDynamicClient) Create(ctx context.Context, obj *unstructured.Unstructured, options metav1.CreateOptions, v any) error {
	data, err := r.c.Resource(r.gvr).Namespace(r.namespace).Create(ctx, obj, options)
	if err != nil {
		return err
	}
	return r.unmarshal(data.UnstructuredContent(), v)
}

func (r *ResourceDynamicClient) Update(ctx context.Context, obj *unstructured.Unstructured, options metav1.UpdateOptions, v any) error {
	data, err := r.c.Resource(r.gvr).Namespace(r.namespace).Update(ctx, obj, options)
	if err != nil {
		return err
	}

	return r.unmarshal(data.UnstructuredContent(), v)
}

func (r *ResourceDynamicClient) Get(ctx context.Context, name string, options metav1.GetOptions, v any) error {
	if r.informer != nil {
		var (
			obj runtime.Object
			err error
		)

		if r.namespace == "" {
			obj, err = r.informer.Lister().Get(name)
		} else {
			obj, err = r.informer.Lister().ByNamespace(r.namespace).Get(name)
		}

		if err != nil {
			klog.Error("lister get object error, ", err, ", ", name)
			return err
		}

		unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
		if err != nil {
			klog.Error("convert to unstructured error, ", err, ", ", name)
			return err
		}

		return r.unmarshal(unstructuredObj, v)
	}

	data, err := r.c.Resource(r.gvr).Namespace(r.namespace).Get(ctx, name, options)
	if err != nil {
		return err
	}
	return r.unmarshal(data.UnstructuredContent(), v)
}

func (r *ResourceDynamicClient) List(ctx context.Context, options metav1.ListOptions, v any) ([]any, error) {
	if r.informer != nil {
		// cached listing
		list, err := r.informer.Lister().ByNamespace(r.namespace).List(labels.Everything())
		if err != nil {
			klog.Error("lister list object error, ", err, ", ", options)
			return nil, err
		}

		ret := make([]any, len(list))
		for _, item := range list {
			unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(item)
			if err != nil {
				klog.Error("convert to unstructured error, ", err, ", ", item)
				return nil, err
			}

			err = r.unmarshal(unstructuredObj, v)
			if err != nil {
				klog.Error("convert object in list error, ", err, ", ", v)
				return nil, err
			}

			ret = append(ret, v)
		}
		return ret, nil
	}

	data, err := r.c.Resource(r.gvr).Namespace(r.namespace).List(ctx, options)
	if err != nil {
		return nil, err
	}

	if len(data.Items) == 0 {
		return nil, nil
	}

	ret := make([]any, len(data.Items))
	for _, item := range data.Items {
		err = r.unmarshal(item.UnstructuredContent(), v)
		if err != nil {
			klog.Error("convert object in list error, ", err, ", ", v)
			return nil, err
		}

		ret = append(ret, v)
	}

	return ret, nil
}
