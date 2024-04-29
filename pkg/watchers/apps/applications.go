package apps

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	appv1 "bytetrade.io/web3os/bfl/internal/ingress/api/app.bytetrade.io/v1alpha1"
	"bytetrade.io/web3os/bfl/pkg/apis/iam/v1alpha1/operator"
	clientset "bytetrade.io/web3os/bfl/pkg/client/clientset/v1alpha1"
	"bytetrade.io/web3os/bfl/pkg/client/dynamic_client"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils/certmanager"
	"bytetrade.io/web3os/bfl/pkg/watchers"

	"github.com/pkg/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

var GVR = schema.GroupVersionResource{
	Group: "app.bytetrade.io", Version: "v1alpha1", Resource: "applications",
}

type Subscriber struct {
	*watchers.Subscriber
	client        clientset.Client
	dynamicClient *dynamic_client.ResourceDynamicClient
}

func (s *Subscriber) WithKubeConfig(config *rest.Config) *Subscriber {
	s.dynamicClient = dynamic_client.NewResourceDynamicClientOrDie().GroupVersionResource(GVR)
	s.client, _ = clientset.NewKubeClient(config)
	return s
}

func (s *Subscriber) HandleEvent() cache.ResourceEventHandler {
	return cache.FilteringResourceEventHandler{
		FilterFunc: func(obj interface{}) bool {
			app, ok := obj.(*appv1.Application)
			if !ok {
				klog.Error("not application resource, invalid obj")
				return false
			}

			if strings.HasPrefix(app.Namespace, "user-space-") || strings.HasPrefix(app.Namespace, "user-system-") {
				return false
			}

			return true
		},

		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eobj := watchers.EnqueueObj{
					Subscribe: s,
					Obj:       obj,
					Action:    watchers.ADD,
				}
				s.Watchers.Enqueue(eobj)
			},
			DeleteFunc: func(obj interface{}) {
				eobj := watchers.EnqueueObj{
					Subscribe: s,
					Obj:       obj,
					Action:    watchers.DELETE,
				}
				s.Watchers.Enqueue(eobj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				eobj := watchers.EnqueueObj{
					Subscribe: s,
					Obj:       newObj,
					Action:    watchers.UPDATE,
				}
				s.Watchers.Enqueue(eobj)
			},
		},
	}
}

func (s *Subscriber) Do(ctx context.Context, obj interface{}, action watchers.Action) error {
	var err error
	var request, ok = obj.(*appv1.Application)
	if !ok {
		return errors.New("invalid object")
	}

	if ok = s.isOwnerApp(request.Spec.Owner); !ok {
		return nil
	}

	klog.Infof("customdomain-status-check queue request: app: %s_%s, action: %d", request.Spec.Name, request.Spec.Namespace, action)

	switch action {
	case watchers.ADD, watchers.UPDATE:
		request, err = s.getObj(request.GetName())
		if err != nil {
			return nil
		}
		obj = request
		if err := s.checkCustomDomainStatus(request); err != nil {
			return fmt.Errorf("%s, app: %s-%s", err.Error(), request.Spec.Name, request.Spec.Namespace)
		}
	case watchers.DELETE:
		return s.removeCustomDomainCnameData(request)
	}
	return nil
}

func (s *Subscriber) checkCustomDomainStatus(app *appv1.Application) error {
	var err error
	customDomains, ok := app.Spec.Settings[constants.ApplicationCustomDomain]
	if !ok || customDomains == "" {
		return nil
	}

	var customDomainsObj = make(map[string]map[string]string)
	if err = json.Unmarshal([]byte(customDomains), &customDomainsObj); err != nil {
		klog.Errorf("customdomain-status-check queue unmarshal custom domains error %+v", err)
		return nil
	}

	if len(customDomainsObj) == 0 {
		return nil
	}

	var existsPending bool
	var existsCustomDomain bool
	for _, customDomainObj := range customDomainsObj {
		var domainStatus string
		customDomainName := customDomainObj[constants.ApplicationThirdPartyDomain]
		customDomainCnameTargetStatus := customDomainObj[constants.ApplicationCustomDomainCnameTargetStatus]
		customDomainCnameStatus := customDomainObj[constants.ApplicationCustomDomainCnameStatus]

		if customDomainName == "" || customDomainCnameTargetStatus == constants.CustomDomainCnameStatusNotset ||
			(customDomainCnameTargetStatus == constants.CustomDomainCnameStatusSet && customDomainCnameStatus == constants.CustomDomainCnameStatusActive) {
			continue
		}

		existsCustomDomain = true
		domainStatus, err = s.checkStatus(customDomainName)
		if err != nil {
			break
		}

		if domainStatus == constants.CustomDomainCnameStatusEmpty ||
			domainStatus == constants.CustomDomainCnameStatusNotset ||
			domainStatus == constants.CustomDomainCnameStatusError {
			err = fmt.Errorf("app custom domain status check invalid: %s", domainStatus)
			break
		}
		customDomainObj[constants.ApplicationCustomDomainCnameStatus] = domainStatus
		if domainStatus == constants.CustomDomainCnameStatusPending {
			existsPending = true
		}
	}

	if !existsCustomDomain {
		return nil
	}

	if err != nil {
		return err
	}

	cdos, err := json.Marshal(customDomainsObj)
	if err != nil {
		return err
	}
	app.Spec.Settings[constants.ApplicationCustomDomain] = string(cdos)
	if err = s.updateApp(app); err != nil {
		return err
	}
	if existsPending {
		return errors.New("app custom domain status check is pending")
	}
	return nil
}

func (s *Subscriber) updateApp(app *appv1.Application) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ab, err := json.Marshal(app)
	if err != nil {
		klog.Errorf("update app marshal app error %+v, app: %s", err, app.GetName())
		return nil
	}
	var obj = make(map[string]interface{})
	err = json.Unmarshal(ab, &obj)
	if err != nil {
		klog.Errorf("update app unmarshal app error %+v, app: %s", err, app.GetName())
		return nil
	}

	err = s.dynamicClient.Update(ctx, &unstructured.Unstructured{Object: obj}, v1.UpdateOptions{}, app)
	if err != nil {
		return err
	}
	return nil
}

func (s *Subscriber) checkStatus(domainName string) (string, error) {
	terminusName, err := s.getTerminusName()
	if err != nil {
		return constants.CustomDomainCnameStatusEmpty, err
	}
	cm := certmanager.NewCertManager(constants.TerminusName(terminusName))

	domainCnameStatus, err := cm.GetCustomDomainCnameStatus(domainName)
	if err != nil {
		return constants.CustomDomainCnameStatusError, nil
	}
	if !domainCnameStatus.Success {
		return constants.CustomDomainCnameStatusNotset, nil
	}

	cnameStatus, err := cm.GetCustomDomainOnCloudflare(domainName)
	if err != nil {
		errmsg := cm.GetCustomDomainErrorStatus(err)
		if errmsg != constants.CustomDomainCnameStatusNone {
			return constants.CustomDomainCnameStatusEmpty, err
		}

		_, err = cm.AddCustomDomainOnCloudflare(domainName)
		if err != nil {
			return constants.CustomDomainCnameStatusEmpty, err
		}
	}
	var sslStatus, hostnameStatus string = constants.CustomDomainCnameStatusPending, constants.CustomDomainCnameStatusPending
	if cnameStatus != nil {
		sslStatus = cnameStatus.SSLStatus
		hostnameStatus = cnameStatus.HostnameStatus
	}

	return s.mergeCnameStatus(sslStatus, hostnameStatus), nil
}

func (s *Subscriber) removeCustomDomainCnameData(app *appv1.Application) error {
	var terminusName, err = s.getTerminusName()
	if err != nil {
		return nil
	}

	customDomainData := app.Spec.Settings[constants.ApplicationCustomDomain]
	if customDomainData == "" {
		return nil
	}

	var entrancesCustomDomain = make(map[string]map[string]interface{})
	if err = json.Unmarshal([]byte(customDomainData), &entrancesCustomDomain); err != nil {
		return nil
	}

	if len(entrancesCustomDomain) == 0 {
		return nil
	}

	cm := certmanager.NewCertManager(constants.TerminusName(terminusName))
	for _, entranceCustomDomain := range entrancesCustomDomain {
		customDomainName, ok := entranceCustomDomain[constants.ApplicationThirdPartyDomain]
		if !ok || customDomainName == nil {
			continue
		}
		_, err = cm.DeleteCustomDomainOnCloudflare(customDomainName.(string))
		if err != nil {
			break
		}
	}
	return err
}

func (s *Subscriber) mergeCnameStatus(sslStatus, hostnameStatus string) string {
	switch {
	case hostnameStatus == sslStatus && sslStatus == constants.CustomDomainCnameStatusActive:
		return constants.CustomDomainCnameStatusActive
	default:
		return constants.CustomDomainCnameStatusPending
	}
}

func (s *Subscriber) getTerminusName() (string, error) {
	op, err := operator.NewUserOperator()
	if err != nil {
		return "", err
	}
	user, err := op.GetUser("")
	if err != nil {
		return "", err
	}
	terminusName := op.GetTerminusName(user)
	if terminusName == "" {
		return "", errors.New("terminus name not found")
	}
	return terminusName, nil
}

func (s *Subscriber) getObj(appName string) (*appv1.Application, error) {
	var app appv1.Application

	if err := s.dynamicClient.Get(context.Background(), appName, v1.GetOptions{}, &app); err != nil {
		return nil, err
	}
	return &app, nil
}

func (s *Subscriber) isOwnerApp(owner string) bool {
	return owner == constants.Username
}
