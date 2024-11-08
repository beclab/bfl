package users

import (
	"context"
	"fmt"

	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/constants"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubesphere.io/api/iam/v1alpha2"
	v1alpha2Clientset "kubesphere.io/kubesphere/pkg/client/clientset/versioned/typed/iam/v1alpha2"
)

type IamUser struct {
	ctx context.Context

	client v1alpha2Clientset.UserInterface
}

func NewIamUser(token string) *IamUser {
	c := runtime.NewKubeClientWithToken(token)
	return &IamUser{
		ctx:    context.Background(),
		client: c.KubeSphere().IamV1alpha2().Users(),
	}
}

func (u *IamUser) GetUser() (*v1alpha2.User, error) {
	return u.client.Get(u.ctx, constants.Username, metav1.GetOptions{})
}

func (u *IamUser) ListUsers() ([]v1alpha2.User, error) {
	users, err := u.client.List(u.ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return users.Items, nil
}

func (u *IamUser) UpdateUser(user *v1alpha2.User) error {
	_, err := u.client.Update(u.ctx, user, metav1.UpdateOptions{})
	return err
}

func (u *IamUser) GetTerminusName() (string, error) {
	user, err := u.GetUser()
	if err != nil {
		return "", err
	}
	if name, ok := user.Annotations[constants.UserAnnotationTerminusNameKey]; ok && name != "" {
		return name, nil
	}
	return "", fmt.Errorf("user olares name not binding")
}

func (u *IamUser) BindingTerminusName(terminusName string) error {
	user, err := u.GetUser()
	if err != nil {
		return err
	}
	if v, ok := user.Annotations[constants.UserAnnotationTerminusNameKey]; ok {
		return fmt.Errorf("user '%s' olares name is already bind, olares name: %s", user.Name, v)
	}

	// update terminus to user annotation
	user.Annotations[constants.UserAnnotationTerminusNameKey] = terminusName
	return u.UpdateUser(user)
}

func (u *IamUser) UnbindingTerminusName() error {
	user, err := u.GetUser()
	if err != nil {
		return err
	}
	delete(user.Annotations, constants.UserAnnotationTerminusNameKey)

	return u.UpdateUser(user)
}

func (u *IamUser) UpdateUserAnnotation(key, value string) error {
RETRY:
	user, err := u.GetUser()
	if err != nil {
		return err
	}
	user.Annotations[key] = value
	if err = u.UpdateUser(user); err != nil && apierrors.IsConflict(err) {
		goto RETRY
	} else if err != nil {
		return err
	}
	return nil
}

func (u *IamUser) GetAnnotation(name string) string {
	user, err := u.GetUser()
	if err != nil {
		return ""
	}
	if v, ok := user.Annotations[name]; ok {
		return v
	}
	return ""
}
