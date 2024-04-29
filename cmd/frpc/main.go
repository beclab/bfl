package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"bytetrade.io/web3os/bfl/internal/frpc"
	"bytetrade.io/web3os/bfl/internal/frpc/controllers"
	"bytetrade.io/web3os/bfl/internal/ingress/api/app.bytetrade.io/v1alpha1"
	"bytetrade.io/web3os/bfl/pkg/apis/iam/v1alpha1/operator"
	"bytetrade.io/web3os/bfl/pkg/constants"

	"github.com/go-resty/resty/v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	// +kubebuilder:scaffold:imports
)

const (
	MAX_RETRY_COUNT = 5
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

var (
	user      string
	frpServer string

	metricsAddr             string
	probeAddr               string
	enableLeaderElection    bool
	enableFrpc              bool
	frpClientConfigMap      string
	frpClientConfigMapLabel string
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	_ = v1alpha1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func flags() error {
	flag.StringVar(&user, "user", "", "The fprc owner username")
	flag.StringVar(&frpServer, "frp-server", "", "The fprc server")
	flag.BoolVar(&enableFrpc, "enable-frpc", true, "Run frpc process")
	flag.Parse()

	// required
	if user == "" {
		return fmt.Errorf("missing flag 'user'")
	}

	if frpServer == "" {
		return fmt.Errorf("missing flag 'frp-server'")
	}

	constants.Username = user

	setupLog.Info("Frpc flags", "username", constants.Username)

	return nil
}

func main() {
	ctrl.SetLogger(zap.New(func(o *zap.Options) {
		o.Development = true
	}))

	if err := flags(); err != nil {
		setupLog.Error(err, "flag error")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
	})

	frpc := controllers.FrpcController{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		Log:            ctrl.Log.WithName("controllers").WithName("FrpcController"),
		Eventer:        mgr.GetEventRecorderFor("frpc-controller"),
		HttpClient:     resty.New().SetTimeout(5 * time.Second),
		ReconcileQueue: make(chan string, frpc.QueueSize),
	}

	constants.FrpServer = getFrpServer()

	if err = frpc.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller FrpcController")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if enableFrpc {
		setupLog.Info("Start frpc process, using default frpc.ini")
		if err = frpc.RunFrpc(); err != nil {
			setupLog.Error(err, "unable to run frpc process")
			os.Exit(1)
		}
	}

	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "unable to start frpc")
		os.Exit(1)
	}
}

func getFrpServer() string {
	var retry int
	var publicDomainIp string
	var userOp, err = operator.NewUserOperator()
	if err != nil {
		return frpServer
	}

	var stopCh = make(chan struct{})
	wait.Until(func() {
		retry = retry + 1
		user, err := userOp.GetUser(constants.Username)
		if err != nil {
			return
		}

		publicDomainIp = userOp.GetUserAnnotation(user, constants.UserAnnotationPublicDomainIp)
		if retry < MAX_RETRY_COUNT && publicDomainIp == "" {
			setupLog.Info(fmt.Sprintf("Frpc start get frpServer from crd failed, continue..."))
			return
		}

		close(stopCh)
	}, 5*time.Second, stopCh)

	if publicDomainIp == "" {
		setupLog.Info(fmt.Sprintf("Frpc start set frpServer from args %s, retries: %d", frpServer, retry))
		publicDomainIp = frpServer
	} else {
		setupLog.Info(fmt.Sprintf("Frpc start set frpServer from user, retries: %d", retry))
	}
	return publicDomainIp
}
