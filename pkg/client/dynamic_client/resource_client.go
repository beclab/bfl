package dynamic_client

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type resourceList[T any] interface {
	GetItems() []T
}

type resourceClient[T any, TL resourceList[T]] struct {
	c *ResourceDynamicClient
}

func NewResourceClient[T any, TL resourceList[T]](gvr schema.GroupVersionResource) (*resourceClient[T, TL], error) {
	ri, err := NewResourceDynamicClient()
	if err != nil {
		return nil, err
	}
	return &resourceClient[T, TL]{c: ri.GroupVersionResource(gvr)}, nil
}

func (u *resourceClient[T, TL]) Get(ctx context.Context, name string, options metav1.GetOptions) (*T, error) {
	var resource T

	err := u.c.Get(ctx, name, options, &resource)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

func (u *resourceClient[T, TL]) List(ctx context.Context, options metav1.ListOptions) ([]T, error) {
	var resourceList TL

	err := u.c.List(ctx, options, &resourceList)
	if err != nil {
		return nil, err
	}

	var resources []T

	for _, r := range resourceList.GetItems() {
		resources = append(resources, r)
	}

	return resources, nil
}

func (u *resourceClient[T, TL]) Update(ctx context.Context, resource *T, options metav1.UpdateOptions) (*T, error) {
	obj, err := ToUnstructured(resource)
	if err != nil {
		return nil, err
	}

	err = u.c.Update(ctx, &unstructured.Unstructured{Object: obj}, options, resource)
	return resource, err
}
