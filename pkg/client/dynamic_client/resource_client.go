package dynamic_client

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type resourceClient[T any] struct {
	c *ResourceDynamicClient
}

func NewResourceClient[T any](gvr schema.GroupVersionResource) (*resourceClient[T], error) {
	ri, err := NewResourceDynamicClient()
	if err != nil {
		return nil, err
	}
	return &resourceClient[T]{c: ri.GroupVersionResource(gvr)}, nil
}

func (u *resourceClient[T]) Get(ctx context.Context, name string, options metav1.GetOptions) (*T, error) {
	var resource T

	err := u.c.Get(ctx, name, options, &resource)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

func (u *resourceClient[T]) List(ctx context.Context, options metav1.ListOptions) ([]*T, error) {
	var r T
	resources, err := u.c.List(ctx, options, &r)
	if err != nil {
		return nil, err
	}

	var ret []*T
	for _, r := range resources {
		ret = append(ret, r.(*T))
	}

	return ret, nil
}

func (u *resourceClient[T]) Update(ctx context.Context, resource *T, options metav1.UpdateOptions) (*T, error) {
	obj, err := ToUnstructured(resource)
	if err != nil {
		return nil, err
	}

	err = u.c.Update(ctx, &unstructured.Unstructured{Object: obj}, options, resource)
	return resource, err
}
