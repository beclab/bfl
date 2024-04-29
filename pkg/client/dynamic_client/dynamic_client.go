package dynamic_client

import (
	"context"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	ctrl "sigs.k8s.io/controller-runtime"
)

var syncOnce sync.Once

type ResourceDynamicClient struct {
	namespace string
	gvr       schema.GroupVersionResource
	c         dynamic.Interface
}

var resourceInterface *ResourceDynamicClient

func init() {
	syncOnce.Do(func() {
		client, err := NewResourceDynamicClient()
		if err != nil {
			panic(err)
		}
		resourceInterface = client
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
	ret := *r
	ret.namespace = ns
	return &ret
}

func (r *ResourceDynamicClient) GroupVersionResource(gvr schema.GroupVersionResource) *ResourceDynamicClient {
	ret := *r
	ret.gvr = gvr
	return &ret
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
	data, err := r.c.Resource(r.gvr).Namespace(r.namespace).Get(ctx, name, options)
	if err != nil {
		return err
	}
	return r.unmarshal(data.UnstructuredContent(), v)
}

func (r *ResourceDynamicClient) List(ctx context.Context, options metav1.ListOptions, v any) error {
	data, err := r.c.Resource(r.gvr).Namespace(r.namespace).List(ctx, options)
	if err != nil {
		return err
	}
	return r.unmarshal(data.UnstructuredContent(), v)
}
