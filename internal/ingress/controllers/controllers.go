package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	v1alpha1App "bytetrade.io/web3os/bfl/internal/ingress/api/app.bytetrade.io/v1alpha1"
	"bytetrade.io/web3os/bfl/internal/ingress/controllers/config"
	ngx_template "bytetrade.io/web3os/bfl/internal/ingress/controllers/template"
	"bytetrade.io/web3os/bfl/internal/ingress/nginx"
	"bytetrade.io/web3os/bfl/internal/ingress/util"
	"bytetrade.io/web3os/bfl/pkg/apis/iam/v1alpha1/operator"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils"
	"bytetrade.io/web3os/bfl/pkg/utils/file"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	iamV1alpha2 "kubesphere.io/api/iam/v1alpha2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type NginxController struct {
	client.Client

	Scheme *runtime.Scheme

	Log logr.Logger

	Eventer record.EventRecorder

	Cfg config.Configuration

	Tc config.TemplateConfig

	command *nginx.NginxCommand

	t ngx_template.TemplateWriter

	// ingress ssl configmap
	sslConfigData map[string]string

	sslCertPath    string
	sslCertKeyPath string

	// user's applications
	apps []v1alpha1App.Application
}

func (r *NginxController) RunNginx() error {
	// init
	r.command = nginx.NewNginxCommand()

	// nginx template object
	ngxTpl, err := ngx_template.NewTemplate(nginx.TemplatePath)
	if err != nil {
		return err
	}
	r.t = ngxTpl

	// start nginx process
	if err = r.startNginx(); err != nil {
		return err
	}
	return nil
}

func (r *NginxController) render() error {
	servers, err := r.generateNginxServers()
	if err != nil {
		return fmt.Errorf("generate nginx server err, %v", err)
	}

	customDomainServers, err := r.generateCustomDomainNginxServers()
	if err != nil {
		klog.Errorf("failed to generate custom domain server, %v", err)
	}

	content, err := r.generateTemplate(servers, customDomainServers)
	// klog.Infof("Generated nginx template file contents:\n%v", string(content))
	if err != nil {
		klog.Errorf("failed to generate nginx template file, %v", err)
		return err
	}

	klog.Infof("Testing nginx.conf using temporary file")
	err = r.testTemplate(content)
	if err != nil {
		klog.Errorf("failed to test nginx file, %v", err)
		return err
	}

	if klog.V(2).Enabled() {
		src, _ := ioutil.ReadFile(nginx.DefNgxCfgPath)
		if !bytes.Equal(src, content) {
			tmpfile, err := ioutil.TempFile("", "new-nginx-cfg")
			if err != nil {
				return err
			}
			defer tmpfile.Close()
			err = ioutil.WriteFile(tmpfile.Name(), content, nginx.PermReadWriteByUser)
			if err != nil {
				return err
			}

			diffOutput, err := exec.Command("diff", "-I", "'# Configuration.*'", "-u", nginx.DefNgxCfgPath,
				tmpfile.Name()).CombinedOutput()
			if err != nil {
				if exitError, ok := err.(*exec.ExitError); ok {
					ws := exitError.Sys().(syscall.WaitStatus)
					if ws.ExitStatus() == 2 {
						klog.Warningf("Failed to executing diff command: %v", err)
					}
				}
			}

			klog.Infof("NGINX configuration changed\n%v", string(diffOutput))

			// we do not defer the deletion of temp files in order
			// to keep them around for inspection in case of error
			os.Remove(tmpfile.Name())
		}
	}

	klog.Infof("Write nginx content to %s", nginx.DefNgxCfgPath)
	err = ioutil.WriteFile(nginx.DefNgxCfgPath, content, nginx.PermReadWriteByUser)
	if err != nil {
		return err
	}

	// reload nginx
	klog.Info("Reloading nginx process")
	out, err := r.command.Reload()
	if err != nil {
		return fmt.Errorf("%v\n%v", err, string(out))
	}

	return nil
}

func (r *NginxController) generateCustomDomainNginxServers() ([]config.CustomServer, error) {
	if r.apps == nil || len(r.apps) == 0 {
		return nil, fmt.Errorf("current userspace has no applications")
	}

	servers := make([]config.CustomServer, 0)
	alias := []string{}

	for _, app := range r.apps {
		if app.Spec.Entrances == nil || len(app.Spec.Entrances) == 0 {
			klog.Warningf("invalid app %q custom domain, ignore it. app=%s", app.Spec.Name, utils.PrettyJSON(app.Spec))
			continue
		}

		for _, entranceServiceAddr := range app.Spec.Entrances {
			if entranceServiceAddr.Host == "" {
				continue
			}
			prefix := app.Spec.Name
			customDomainEntrancesMap, err := getSettingsMap(&app, constants.ApplicationCustomDomain)
			if err != nil {
				klog.Warningf("failed to unmarshal application custom domain, %q, %s, %s, %v", prefix, app.Spec.Name, app.Spec.Appid, err)
				continue
			}

			if len(customDomainEntrancesMap) == 0 {
				continue
			}

			customDomainEntranceMap, ok := customDomainEntrancesMap[entranceServiceAddr.Name]
			if !ok {
				continue
			}

			customDomainName := customDomainEntranceMap[constants.ApplicationThirdPartyDomain]

			if customDomainName == "" {
				continue
			}

			if r.sslConfigData != nil {
				zone := r.sslConfigData["zone"]
				certName, keyName := fmt.Sprintf("x.%s.crt", zone), fmt.Sprintf("x.%s.key", zone)

				certPath := filepath.Join(nginx.DefNgxSSLCertificationPath, certName)
				keyPath := filepath.Join(nginx.DefNgxSSLCertificationPath, keyName)

				s := config.CustomServer{
					Server: config.Server{
						Hostname:   customDomainName,
						Aliases:    alias,
						EnableSSL:  true,
						EnableAuth: true,
						Locations: []config.Location{
							{
								Prefix:    "/",
								ProxyPass: fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", entranceServiceAddr.Host, app.Spec.Namespace, entranceServiceAddr.Port),
							},
						},
						EnableAnalytics: false,
					},
					SslCertPath: certPath,
					SslKeyPath:  keyPath,
				}
				servers = append(servers, s)
			}
		}
	}

	return servers, nil
}

func (r *NginxController) generateNginxServers() ([]config.Server, error) {
	if r.apps == nil || len(r.apps) == 0 {
		return nil, fmt.Errorf("current userspace has no applications")
	}

	servers := make([]config.Server, 0)

	// get the bfl service
	var svc corev1.Service
	err := r.Get(context.TODO(), types.NamespacedName{Namespace: constants.Namespace, Name: constants.BFLServiceName}, &svc)
	if err != nil {
		return nil, fmt.Errorf("no bfl service found, %v", err)
	}

	latestAppPort := func(portName string) int {
		// compute the latest and available app port
		var latestPort, maxAppPort int32

		if len(svc.Spec.Ports) < 1 {
			return int(constants.AppListenFromPort)
		} else {
			maxPort := svc.Spec.Ports[0].Port
			for _, p := range svc.Spec.Ports {
				if p.Name == portName {
					// never used
					// latestPort = p.Port
					break
				}
				if p.Port > maxPort {
					maxPort = p.Port
				}
				if strings.HasPrefix(p.Name, constants.AppPortNamePrefix) && p.Port > maxAppPort {
					maxAppPort = p.Port
				}
			}
			if maxAppPort+1 > constants.AppListenFromPort && maxAppPort+1 < maxPort {
				latestPort = maxAppPort + 1
			} else if maxAppPort < constants.AppListenFromPort {
				latestPort = constants.AppListenFromPort
			} else {
				latestPort = maxPort + 1
			}
		}
		klog.InfoS("Figure out the latest port", "maxAppPort", maxAppPort, "latestPort", latestPort)

		portExists := false

		for _, app := range svc.Spec.Ports {
			if portName == app.Name {
				app.Port = latestPort
				app.TargetPort = intstr.FromInt(int(latestPort))
				portExists = true
				break
			}
		}
		if !portExists {
			// update svc
			svcPort := corev1.ServicePort{
				Name:       portName,
				Protocol:   "TCP",
				Port:       latestPort,
				TargetPort: intstr.FromInt(int(latestPort)),
			}
			svc.Spec.Ports = append(svc.Spec.Ports, svcPort)
		}
		return int(latestPort)
	}

	// For each applications port server
	for _, app := range r.apps {
		if app.Spec.Entrances == nil || len(app.Spec.Entrances) == 0 {
			klog.Warningf("invalid app %q, ignore it. app=%s", app.Spec.Name, utils.PrettyJSON(app.Spec))
			continue
		}

		for _, entrance := range app.Spec.Entrances {
			if entrance.Host == "" {
				continue
			}
			appPortName := fmt.Sprintf("%s%s", constants.AppPortNamePrefix, app.Spec.Name)
			appPort := latestAppPort(appPortName)

			s := config.Server{
				Port: appPort,
				Locations: []config.Location{
					{
						Prefix:    "/",
						ProxyPass: fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", entrance.Host, app.Spec.Namespace, entrance.Port),
					},
				},
			}
			servers = append(servers, s)
		}
	}
	klog.Infof("Prepared and updating service ports:\n%v", utils.PrettyJSON(svc.Spec.Ports))
	err = r.Update(context.TODO(), &svc)
	if err != nil {
		return nil, err
	}

	// For each domain servers

	if r.sslConfigData != nil {
		// certificate files
		zone, certData, keyData := r.sslConfigData["zone"], r.sslConfigData["cert"], r.sslConfigData["key"]
		certName, keyName := fmt.Sprintf("x.%s.crt", zone), fmt.Sprintf("x.%s.key", zone)

		r.sslCertPath = filepath.Join(nginx.DefNgxSSLCertificationPath, certName)
		r.sslCertKeyPath = filepath.Join(nginx.DefNgxSSLCertificationPath, keyName)

		if err := r.writeCertificates(certData, keyData); err != nil {
			return nil, err
		}

		var isEphemeral bool
		var _servers []config.Server

		op, err := operator.NewUserOperator()
		if err != nil {
			return nil, err
		}
		user, err := op.GetUser("")
		if err != nil {
			return nil, err
		}
		language := op.GetUserAnnotation(user, "bytetrade.io/language")

		if ephemeral, ok := r.sslConfigData["ephemeral"]; !ok {
			_servers = r.addDomainServers(false, zone, language)
		} else {
			isEphemeral, err = strconv.ParseBool(ephemeral)
			if err != nil {
				return nil, err
			}
			_servers = r.addDomainServers(isEphemeral, zone, language)
		}

		servers = append(servers, _servers...)
	}

	return servers, nil
}

func (r *NginxController) writeCertificates(certData, keyData string) error {
	if !file.Exists(nginx.DefNgxSSLCertificationPath) {
		err := os.MkdirAll(nginx.DefNgxSSLCertificationPath, 0755)
		if err != nil {
			return err
		}
	}

	err := file.WriteFile(r.sslCertPath, certData, false)
	if err != nil {
		return err
	}

	err = file.WriteFile(r.sslCertKeyPath, keyData, false)
	if err != nil {
		return err
	}
	return nil
}

func (r *NginxController) testTemplate(cfg []byte) error {
	if len(cfg) == 0 {
		return fmt.Errorf("invalid NGINX configuration (empty)")
	}

	var tempNginxPattern = "nginx-cfg"

	tmpFile, err := ioutil.TempFile("", tempNginxPattern)
	if err != nil {
		return err
	}
	defer tmpFile.Close()

	err = ioutil.WriteFile(tmpFile.Name(), cfg, nginx.PermReadWriteByUser)
	if err != nil {
		return err
	}

	out, err := r.command.Test(tmpFile.Name())
	if err != nil {
		return fmt.Errorf("%v\n%v", err, string(out))
	}

	os.Remove(tmpFile.Name())
	return nil
}

func (r *NginxController) getMasterNodesIps() ([]string, error) {
	var nodeLists corev1.NodeList
	if err := r.List(context.TODO(), &nodeLists, client.HasLabels{"node-role.kubernetes.io/master"}); err != nil {
		return nil, err
	}

	addrs := make([]string, 0)

	for _, node := range nodeLists.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP && addr.Address != "" {
				addrs = append(addrs, addr.Address)
			}
		}
	}
	return addrs, nil
}

func (r *NginxController) generateTemplate(servers []config.Server, customDomainServers []config.CustomServer) ([]byte, error) {
	// new nginx configuration
	cfg := config.NewDefault()
	r.Cfg = cfg

	op, err := operator.NewUserOperator()
	if err != nil {
		return nil, err
	}
	user, err := op.GetUser("")
	if err != nil {
		return nil, err
	}

	masterNodeIPs, err := r.getMasterNodesIps()
	if err != nil {
		return nil, err
	}

	// init others
	tc := config.TemplateConfig{
		ProxySetHeaders: map[string]string{},
		AddHeaders:      map[string]string{},
		BacklogSize:     util.SysctlSomaxconn(),
		HealthzURI:      nginx.HealthPath,
		Cfg:             cfg,
		IsIPV6Enabled:   false,
		ListenPorts: &config.ListenPorts{
			HTTP:  80,
			HTTPS: 443,
		},

		RealIpFrom:          masterNodeIPs,
		Servers:             servers,
		CustomDomainServers: customDomainServers,

		PID:                   nginx.PID,
		StatusPath:            nginx.StatusPath,
		StatusPort:            nginx.StatusPort,
		StreamPort:            nginx.StreamPort,
		SSLCertificatePath:    r.sslCertPath,
		SSLCertificateKeyPath: r.sslCertKeyPath,
		UserName:              constants.Username,
		UserZone:              op.GetUserZone(user),
	}

	isEphemeral, err := op.UserIsEphemeralDomain(user)
	if err == nil && isEphemeral {
		tc.IsEphemeralUser = true
	}

	r.Tc = tc

	content, err := r.t.Write(tc)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func (r *NginxController) startNginx() (err error) {
	if nginx.IsRunning() {
		r.Log.Info("Nginx is running, ignore")
		return
	}

	// validate cfg file before start nginx process
	_, err = r.command.Test(nginx.DefNgxCfgPath)
	if err != nil {
		return
	}

	cmd := r.command.StartCmd()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return
	}
	return cmd.Wait()
}

//+kubebuilder:rbac:groups=app.bytetrade.io,resources=applications,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=app.bytetrade.io,resources=applications/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=app.bytetrade.io,resources=applications/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile

func (r *NginxController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithName("Reconcile")
	log.Info("request resource name and namespace", "name", req.Name, "namespace", req.Namespace)

	var (
		err             error
		needRender      bool
		c               corev1.ConfigMap
		applicationList v1alpha1App.ApplicationList
		customDomains   []string
	)

	modifyAllowedDomainTimestamp := func() error {
		userOp, err := operator.NewUserOperator()
		if err != nil {
			return errors.Errorf("new user operator err, %v", err)
		}
		user, err := userOp.GetUser(constants.Username)
		if err != nil {
			return errors.Errorf("get user err, %v", err)
		}

		if err = userOp.UpdateUser(user, []func(*iamV1alpha2.User){
			func(u *iamV1alpha2.User) {
				u.Annotations[constants.UserAllowedDomainAccessPolicy] = fmt.Sprintf("%d", time.Now().Unix())
			},
		}); err != nil {
			return errors.Errorf("update user err, %v", err)
		}
		return nil
	}

	err = r.Get(ctx, types.NamespacedName{
		Namespace: constants.Namespace,
		Name:      constants.NameSSLConfigMapName}, &c)

	if err != nil && !apierrors.IsNotFound(err) {
		log.Error(err, "failed to get configmap")
		return ctrl.Result{Requeue: true, RequeueAfter: 2 * time.Second}, err
	}
	if err != nil && apierrors.IsNotFound(err) {
		if r.sslConfigData != nil {
			r.sslConfigData = nil
			needRender = true
		}
	} else {
		if c.Data != nil {
			r.sslConfigData = c.Data
			needRender = true
		}
	}

	formatCustomDomain := func(customDomainSettings string) []string {
		var settings = make(map[string]map[string]string)
		if err := json.Unmarshal([]byte(customDomainSettings), &settings); err != nil {
			return nil
		}

		if len(settings) == 0 {
			return nil
		}

		var customDomains []string

		for _, v := range settings {
			customDomain, ok := v[constants.ApplicationThirdPartyDomain]
			if ok && customDomain != "" {
				customDomains = append(customDomains, customDomain)
			}
		}

		return customDomains
	}

	// apps
	if err = r.List(ctx, &applicationList, client.InNamespace("")); err != nil {
		log.Error(err, "failed to list applications")
		return ctrl.Result{Requeue: true, RequeueAfter: 2 * time.Second}, err
	} else {
		var ownerApps []v1alpha1App.Application

		for _, app := range applicationList.Items {
			// filter apps
			if app.Spec.Name == "" && app.Spec.Appid == "" { // || app.Spec.Entrances == nil || len(app.Spec.Entrances) == 0
				log.WithValues("appName", app.Spec.Name).Info("invalid application, no app name or appid")
				continue
			}
			if app.Spec.Owner == constants.Username {
				ownerApps = append(ownerApps, app)
				existedCustomDomain := formatCustomDomain(app.Spec.Settings[constants.ApplicationCustomDomain])
				if existedCustomDomain != nil && len(existedCustomDomain) > 0 {
					customDomains = append(customDomains, existedCustomDomain...)
				}
			}
		}
		sort.Slice(ownerApps, func(i, j int) bool {
			return ownerApps[i].CreationTimestamp.Before(&ownerApps[j].CreationTimestamp)
		})

		if r.isAppsChanged(ownerApps) {
			r.apps = ownerApps
			needRender = true
		}
	}

	if needRender {
		// notify to render nginx config, and reload nginx process
		time.Sleep(300 * time.Millisecond)
		if err := r.render(); err != nil {
			log.Error(err, "unable to render nginx config error")
			return ctrl.Result{}, nil
		}

		if err = modifyAllowedDomainTimestamp(); err != nil {
			log.Error(err, "modify allowed domain level by tailscale")
			return ctrl.Result{}, nil
		}
	}

	return ctrl.Result{}, nil
}

func (r *NginxController) isAppsChanged(apps []v1alpha1App.Application) bool {
	if r.apps == nil && len(apps) > 0 {
		return true
	}

	if len(r.apps) != len(apps) {
		return true
	}

	getCachedApp := func(name string) *v1alpha1App.Application {
		for _, app := range r.apps {
			if app.Name == name {
				return &app
			}
		}
		return nil
	}

	var isDiff bool

	for _, app := range apps {
		cachedApp := getCachedApp(app.Name)
		isDiff = cachedApp == nil || (cachedApp != nil && !reflect.DeepEqual(cachedApp.Spec, app.Spec))
		if isDiff {
			break
		}
	}
	return isDiff
}

func (r *NginxController) SetupWithManager(mgr ctrl.Manager) error {
	c, err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}, builder.WithPredicates(predicate.Funcs{
			GenericFunc: func(e event.GenericEvent) bool { return false },
			CreateFunc:  func(e event.CreateEvent) bool { return isOwnerConfigmap(e.Object) },
			DeleteFunc:  func(e event.DeleteEvent) bool { return isOwnerConfigmap(e.Object) },
			UpdateFunc: func(e event.UpdateEvent) bool {
				if isCustomDomainCertConfigmap(e.ObjectOld, e.ObjectNew) {
					return true
				}

				if !isOwnerConfigmap(e.ObjectOld, e.ObjectNew) {
					return false
				}
				old, ok1 := e.ObjectOld.(*corev1.ConfigMap)
				_new, ok2 := e.ObjectNew.(*corev1.ConfigMap)
				if !(ok1 && ok2) || reflect.DeepEqual(old.Data, _new.Data) {
					return false
				}
				return true
			},
		})).
		Build(r)

	if err != nil {
		return err
	}

	// watch user applications
	return c.Watch(&source.Kind{Type: &v1alpha1App.Application{}},
		handler.EnqueueRequestsFromMapFunc(
			func(object client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{
					Namespace: object.GetNamespace(),
					Name:      object.GetName(),
				}}}
			}),
		predicate.Funcs{
			GenericFunc: func(e event.GenericEvent) bool { return false },
			CreateFunc:  func(e event.CreateEvent) bool { return isOwnerApp(e.Object) },
			DeleteFunc:  func(e event.DeleteEvent) bool { return isOwnerApp(e.Object) },
			UpdateFunc: func(e event.UpdateEvent) bool {
				if !isOwnerApp(e.ObjectOld, e.ObjectNew) {
					return false
				}
				old, ok1 := e.ObjectOld.(*v1alpha1App.Application)
				_new, ok2 := e.ObjectNew.(*v1alpha1App.Application)
				if !(ok1 && ok2) || reflect.DeepEqual(old.Spec, _new.Spec) {
					return false
				}
				return true
			},
		},
	)
}

func isOwnerApp(objs ...client.Object) bool {
	var isTrue bool
	for _, obj := range objs {
		app, ok := obj.(*v1alpha1App.Application)
		isTrue = ok && app.Spec.Owner == constants.Username
	}
	return isTrue
}

func isOwnerConfigmap(objs ...client.Object) bool {
	var isTrue bool
	for _, obj := range objs {
		cm, ok := obj.(*corev1.ConfigMap)
		isTrue = ok && cm.Namespace == constants.Namespace &&
			cm.Name == constants.NameSSLConfigMapName
	}
	return isTrue
}

func isCustomDomainCertConfigmap(objs ...client.Object) bool {
	var isTrue bool
	for _, obj := range objs {
		cm, ok := obj.(*corev1.ConfigMap)
		isTrue = ok && strings.Index(cm.Name, constants.ApplicationThirdPartyDomainCertKeySuffix) > 0
	}
	return isTrue
}

func getSettingsMap(app *v1alpha1App.Application, key string) (map[string]map[string]string, error) {
	var r = make(map[string]map[string]string)
	var d, ok = app.Spec.Settings[key]
	if !ok {
		return r, nil
	}
	err := json.Unmarshal([]byte(d), &r)
	if err != nil {
		return r, err
	}

	return r, nil
}

func getAppEntrancesHostName(entrancescount, index int, appid string) string {
	if entrancescount == 1 {
		return fmt.Sprintf("%s", appid)
	}
	return fmt.Sprintf("%s%d", appid, index)
}
