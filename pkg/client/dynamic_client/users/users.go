package users

import (
	"context"

	"bytetrade.io/web3os/bfl/pkg/client/dynamic_client"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	iamV1alpha2 "kubesphere.io/api/iam/v1alpha2"
)

var gvr = schema.GroupVersionResource{
	Group:    iamV1alpha2.SchemeGroupVersion.Group,
	Version:  iamV1alpha2.SchemeGroupVersion.Version,
	Resource: iamV1alpha2.ResourcesPluralUser,
}

type ResourceUserClient struct {
	c *dynamic_client.ResourceDynamicClient
}

func NewResourceUserClient() (*ResourceUserClient, error) {
	ri, err := dynamic_client.NewResourceDynamicClient()
	if err != nil {
		return nil, err
	}
	return &ResourceUserClient{c: ri.GroupVersionResource(gvr)}, nil
}

func NewResourceUserClientOrDie() *ResourceUserClient {
	ri := dynamic_client.NewResourceDynamicClientOrDie()
	return &ResourceUserClient{c: ri.GroupVersionResource(gvr)}
}

func (u *ResourceUserClient) Create(ctx context.Context, user iamV1alpha2.User, options metav1.CreateOptions) (*iamV1alpha2.User, error) {
	obj, err := dynamic_client.ToUnstructured(user)
	if err != nil {
		return nil, err
	}

	err = u.c.Create(ctx, &unstructured.Unstructured{Object: obj}, options, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (u *ResourceUserClient) Delete(ctx context.Context, name string, options metav1.DeleteOptions) error {
	return u.c.Delete(ctx, name, options)
}

func (u *ResourceUserClient) Update(ctx context.Context, user *iamV1alpha2.User, options metav1.UpdateOptions) (*iamV1alpha2.User, error) {
	obj, err := dynamic_client.ToUnstructured(user)
	if err != nil {
		return nil, err
	}

	err = u.c.Update(ctx, &unstructured.Unstructured{Object: obj}, options, user)
	return user, err
}

func (u *ResourceUserClient) List(ctx context.Context, options metav1.ListOptions) ([]iamV1alpha2.User, error) {
	var userList iamV1alpha2.UserList

	err := u.c.List(ctx, options, &userList)
	if err != nil {
		return nil, err
	}

	var users []iamV1alpha2.User

	for _, user := range userList.Items {
		user := user
		users = append(users, user)
	}
	return users, nil
}

func (u *ResourceUserClient) Get(ctx context.Context, name string, options metav1.GetOptions) (*iamV1alpha2.User, error) {
	var user iamV1alpha2.User

	err := u.c.Get(ctx, name, options, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
