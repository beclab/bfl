package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sync"
	"time"

	"bytetrade.io/web3os/bfl/internal/frpc"
	"bytetrade.io/web3os/bfl/internal/frpc/command"
	v1alpha1App "bytetrade.io/web3os/bfl/internal/ingress/api/app.bytetrade.io/v1alpha1"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"github.com/go-logr/logr"
	"github.com/go-resty/resty/v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type FrpcController struct {
	client.Client
	Scheme         *runtime.Scheme
	Log            logr.Logger
	Eventer        record.EventRecorder
	HttpClient     *resty.Client
	command        *command.FrpcCommand
	ReconcileQueue chan string
	sync.Mutex
}

func (f *FrpcController) RunFrpc() error {
	f.command = command.NewFrpcCommand()

	if err := f.getConfig(); err != nil {
		return err
	}

	if err := f.startFrpc(); err != nil {
		return err
	}

	go f.runQueue()

	return nil
}

func (f *FrpcController) runQueue() {
	for {
		select {
		case app, ok := <-f.ReconcileQueue:
			if !ok {
				f.ReconcileQueue = make(chan string, frpc.QueueSize)
				continue
			}
			f.Log.Info("Frpc reconcile queue", "app", app)

			f.updateFrpcConfig()
		}
	}
}

func (f *FrpcController) updateFrpcConfig() {
	f.Lock()
	defer f.Unlock()
	apps, err := f.getApps(context.Background())
	if err != nil {
		f.Log.Error(err, "Frpc get apps error")
	}

	if apps == nil || len(apps.Items) == 0 {
		return
	}

	domains, err := f.getCustomDomains(apps)
	if err != nil {
		return
	}

	if err = f.command.UpdateCustomDomains(domains); err != nil {
		f.Log.Error(err, "Frpc update custom domains error")
		return
	}

	// f.Log.Info(fmt.Sprintf("Frpc update config data: %s", f.command.GetTemplate()))

	f.command.Reload()
}

func (f *FrpcController) getConfig() error {
	return f.command.GetFrpcConfig()
}

func (f *FrpcController) startFrpc() (err error) {
	if command.IsRunning() {
		f.Log.Info("Frpc is running, ignore")
		return
	}

	if err = f.command.GenerateConfig(); err != nil {
		f.Log.Error(err, "Frpc generate frpc.ini error")
		return
	}
	f.Log.Info(fmt.Sprintf("Frpc start config data: %s", f.command.GetTemplate()))

	_, err = f.command.Test("")
	if err != nil {
		return err
	}
	cmd := f.command.StartCmd()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err = cmd.Start(); err != nil {
		return err
	}

	return nil
}

// +kubebuilder:rbac:groups=app.bytetrade.io,resources=applications,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=app.bytetrade.io,resources=applications/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=app.bytetrade.io,resources=applications/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (f *FrpcController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	f.ReconcileQueue <- req.Name

	return ctrl.Result{}, nil
}

func (f *FrpcController) SetupWithManager(mgr ctrl.Manager) error {
	_, err := ctrl.NewControllerManagedBy(mgr).For(&v1alpha1App.Application{}, builder.WithPredicates(predicate.Funcs{
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
		CreateFunc: func(ce event.CreateEvent) bool {
			return isOwnerApp(ce.Object)
		},
		DeleteFunc: func(de event.DeleteEvent) bool {
			return isOwnerApp(de.Object)
		},
		UpdateFunc: func(ue event.UpdateEvent) bool {
			if !isOwnerApp(ue.ObjectOld, ue.ObjectNew) {
				return false
			}
			old, ok1 := ue.ObjectOld.(*v1alpha1App.Application)
			_new, ok2 := ue.ObjectNew.(*v1alpha1App.Application)
			if !(ok1 && ok2) || reflect.DeepEqual(old.Spec, _new.Spec) {
				return false
			}
			return true
		},
	})).Build(f)

	if err != nil {
		return err
	}

	return nil
}

func (f *FrpcController) getApps(parentCtx context.Context) (*v1alpha1App.ApplicationList, error) {
	ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
	defer cancel()

	var err error
	var appList v1alpha1App.ApplicationList

	if err = f.List(ctx, &appList, client.InNamespace("")); err != nil {
		return nil, err
	}

	return &appList, nil
}

func (f *FrpcController) getCustomDomains(apps *v1alpha1App.ApplicationList) (customDomains []string, err error) {
	for _, app := range apps.Items {
		var settings = app.Spec.Settings
		if settings == nil || len(settings) == 0 {
			continue
		}

		var customDomainSettings = settings[constants.ApplicationCustomDomain]
		if customDomainSettings == "" {
			continue
		}

		var r = map[string]map[string]string{}
		if err = json.Unmarshal([]byte(customDomainSettings), &r); err != nil {
			continue
		}

		for _, v := range r {
			if domain := v[constants.ApplicationThirdPartyDomain]; domain != "" {
				customDomains = append(customDomains, domain)
			}
		}
	}
	return
}

func isOwnerApp(objs ...client.Object) bool {
	var isTrue = len(objs) != 0
	for _, obj := range objs {
		app, ok := obj.(*v1alpha1App.Application)
		isTrue = ok && app.Spec.Owner == constants.Username && isTrue
	}
	return isTrue
}
