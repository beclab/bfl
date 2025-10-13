package app

import (
	"context"
	"fmt"
	"os"
	"time"

	"bytetrade.io/web3os/bfl/pkg/watchers/reverse_proxy"
	"bytetrade.io/web3os/bfl/pkg/watchers/systemenv"
	corev1 "k8s.io/api/core/v1"

	"bytetrade.io/web3os/bfl/internal/ingress/api/app.bytetrade.io/v1alpha1"
	"bytetrade.io/web3os/bfl/internal/log"
	"bytetrade.io/web3os/bfl/pkg/apiserver"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/signals"
	"bytetrade.io/web3os/bfl/pkg/task"
	"bytetrade.io/web3os/bfl/pkg/utils"
	"bytetrade.io/web3os/bfl/pkg/watchers"
	"bytetrade.io/web3os/bfl/pkg/watchers/apps"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
)

var logLevel string

func NewAPPServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bfl",
		Short: "REST API for launcher",
		Long:  `The BFL ( Backend For Launcher ) provides REST API interfaces for the launcher`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := Run(); err != nil {
				log.Errorf("failed to run apiserver: %+v", err)
				os.Exit(1)
			}
		},
	}

	cmd.PersistentFlags().StringVarP(&logLevel, "log-level", "", "debug", "logging level, debug/info/warn/error/panic/fatal")

	// custom flags
	cmd.PersistentFlags().StringVarP(&constants.Username, "username", "u", "", "username for current userspace")
	cmd.PersistentFlags().StringVarP(&constants.Namespace, "namespace", "n", utils.EnvOrDefault("BFL_NAMESPACE", ""), "namespace for bfl")
	cmd.PersistentFlags().StringVarP(&constants.KubeSphereAPIHost, "ks-apiserver", "s", "ks-apiserver.kubesphere-system", "kubesphere api server")
	cmd.PersistentFlags().StringVarP(&constants.APIServerListenAddress, "listen", "l", ":8080", "listen address")

	return cmd
}

func Run() error {
	log.InitLog(logLevel)

	if constants.Username == "" || constants.KubeSphereAPIHost == "" {
		return fmt.Errorf("flag 'username' or 'ks-apiserver' can not be empty")
	}

	if constants.Namespace == "" {
		return fmt.Errorf("bfl env 'BFL_NAMESPACE' is not set")
	}

	log.Infow("startup flags",
		"username", constants.Username,
		"namespace", constants.Namespace,
		"ksAPIServer", constants.KubeSphereAPIHost,
		"listen", constants.APIServerListenAddress,
		"bflServiceName", constants.BFLServiceName,
		"indexAppEndpoint", constants.IndexAppEndpoint,
		"appListenPortFrom", constants.AppListenFromPort,
		"appPortNamePrefix", constants.AppPortNamePrefix,
		"requestURLNoAuthList", constants.RequestURLWhiteList,
	)

	// watchers
	config := ctrl.GetConfigOrDie()
	ctx, cancel := context.WithCancel(context.Background())
	_ = signals.SetupSignalHandler(ctx, cancel)

	w := watchers.NewWatchers(ctx, config, 0)
	err := watchers.AddToWatchers[v1alpha1.Application](w, apps.GVR,
		(&apps.Subscriber{Subscriber: watchers.NewSubscriber(w)}).WithKubeConfig(config).HandleEvent())
	if err != nil {
		return fmt.Errorf("failed to add app watcher: %w", err)
	}
	reverseProxySubscriber, err := reverse_proxy.NewSubscriber(w)
	if err != nil {
		return fmt.Errorf("failed to initialize reverse proxy subscriber: %v", err)
	}
	err = watchers.AddToWatchers[corev1.ConfigMap](w, reverse_proxy.GVR, reverseProxySubscriber.Handler())
	if err != nil {
		return fmt.Errorf("failed to add reverse proxy watcher: %w", err)
	}
	sysEnvSubscriber := systemenv.NewSubscriber(w)
	// unstructured
	err = watchers.AddToWatchers[map[string]interface{}](w, systemenv.GVR, sysEnvSubscriber.Handler())
	if err != nil {
		return fmt.Errorf("failed to add systemenv watcher: %w", err)
	}
	log.Info("start watchers")
	go w.Run(1)

	// tasks
	log.Info("start task loop")
	go task.Run()

	// change ip
	log.Info("watch entrance ip forever")
	go wait.Forever(watchEntranceIP, 30*time.Second)

	// new server
	log.Info("init and new apiserver")
	s, err := apiserver.New()
	if err != nil {
		return err
	}

	if err = s.PrepareRun(); err != nil {
		return err
	}

	return s.Run()
}
