package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"bytetrade.io/web3os/bfl/internal/log"
	"bytetrade.io/web3os/bfl/pkg/apis/iam/v1alpha1/operator"
	"bytetrade.io/web3os/bfl/pkg/apis/iam/v1alpha1/users"
	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	v1alpha1client "bytetrade.io/web3os/bfl/pkg/client/clientset/v1alpha1"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/task"
	"bytetrade.io/web3os/bfl/pkg/utils"
	"bytetrade.io/web3os/bfl/pkg/utils/certmanager"

	iamV1alpha2 "github.com/beclab/api/iam/v1alpha2"
	"github.com/pkg/errors"
	batchV1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	aruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	applyBatchv1 "k8s.io/client-go/applyconfigurations/batch/v1"
	applyCorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	applyMetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/klog"
	"k8s.io/utils/pointer"
)

var (
	scheme = aruntime.NewScheme()
)

func init() {
	utilruntime.Must(iamV1alpha2.AddToScheme(scheme))
}

var defaultWaitTimeout = 1 * time.Hour

type State int

const (
	_ State = iota

	Pending
	Running
	Failed
	Succeeded

	CheckL4Proxy
	CheckReverseProxyAgent
	GenerateCert
	ConfigureIngressHTTPs
	CheckTunnel
)

type TaskResult struct {
	State State  `json:"state"`
	Err   string `json:"err"`
}

func (t TaskResult) String() string {
	bs, _ := json.Marshal(t)
	return string(bs)
}

func GetEnableHTTPSTaskState(username string) (*TaskResult, error) {
	userOp, err := operator.NewUserOperator()
	if err != nil {
		return nil, err
	}

	user, err := userOp.GetUser(username)
	if err != nil {
		return nil, err
	}

	var t TaskResult

	if v := userOp.GetUserAnnotation(user, constants.EnableSSLTaskResultAnnotationKey); v != "" {
		err = json.Unmarshal([]byte(v), &t)
		if err != nil {
			return nil, err
		}
		return &t, nil
	}

	return nil, errors.New("not started")
}

type EnableHTTPSTaskOption struct {
	GenerateURL        string
	AccessToken        string
	ReverseProxyEnable bool
	WaitTimeout        *time.Duration

	Name string

	ReverseProxyAgentNamespace          string
	ReverseProxyAgentDeploymentName     string
	ReverseProxyAgentDeploymentReplicas int32

	L4ProxyNamespace          string
	L4ProxyDeploymentName     string
	L4ProxyDeploymentReplicas int32
}

type EnableHTTPSTask struct {
	o          *EnableHTTPSTaskOption
	ctx        context.Context
	iamUser    *users.IamUser
	kubeClient v1alpha1client.ClientInterface

	cm certmanager.Interface
}

var _ task.LocalTaskInterface = &EnableHTTPSTask{}

func NewEnableHTTPSTask(option *EnableHTTPSTaskOption) (*EnableHTTPSTask, error) {
	if option.Name == "" {
		return nil, fmt.Errorf("olares name must be provided")
	}

	if option.WaitTimeout == nil {
		option.WaitTimeout = pointer.Duration(defaultWaitTimeout)
	}
	iamUser, err := users.NewIamUser()
	if err != nil {
		return nil, err
	}
	kubeClient, err := runtime.NewKubeClientWithToken(option.AccessToken)
	if err != nil {
		return nil, err
	}

	t := &EnableHTTPSTask{
		cm:         certmanager.NewCertManager(constants.TerminusName(option.Name)),
		o:          option,
		ctx:        context.TODO(),
		iamUser:    iamUser,
		kubeClient: kubeClient,
	}

	err = t.UpdateTaskState(TaskResult{State: Pending})
	return t, err
}

func (t *EnableHTTPSTask) UpdateTaskState(taskResult TaskResult) error {
	err := t.iamUser.UpdateUserAnnotation(constants.EnableSSLTaskResultAnnotationKey, taskResult.String())
	if err != nil {
		return err
	}

	var status constants.WizardStatus
	switch taskResult.State {
	case Failed:
		status = constants.NetworkActivateFailed
	case Succeeded:
		status = constants.WaitResetPassword
	}

	if status != "" {
		if e := t.iamUser.UpdateUserAnnotation(constants.UserTerminusWizardStatus, string(status)); e != nil {
			klog.Errorf("update user err, %v", err)
		}
	}

	return nil
}

func (t *EnableHTTPSTask) waitForDeploymentReady(name, namespace string, replicas int32) bool {
	tc := time.After(*t.o.WaitTimeout)

	for {
		deployment, err := t.kubeClient.Kubernetes().AppsV1().
			Deployments(namespace).Get(t.ctx, name, metav1.GetOptions{})
		if err != nil {
			log.Errorf("check deployment is ready, name: %q, namespace: %q, got err, %v", name, namespace, err)
		} else {
			if deployment != nil && deployment.Status.AvailableReplicas == replicas {
				return true
			}
		}

		select {
		case <-tc:
			log.Errorf("check deployment, timed out in %v seconds", t.o.WaitTimeout.Seconds())
			return false
		default:
			time.Sleep(5 * time.Second)
		}
	}
}

func (t *EnableHTTPSTask) updateUserAnnotation(zone string) (err error) {
	// add zone to user annotations
	err = t.iamUser.UpdateUserAnnotation(constants.UserAnnotationZoneKey, zone)
	if err != nil {
		return
	}
	return t.iamUser.UpdateUserAnnotation(constants.UserAnnotationIsEphemeral, "false")
}

func (t *EnableHTTPSTask) newApplyDownloadCertCronJob(expiredAt string) error {
	forbidConcurrent := batchV1.ForbidConcurrent
	restartOnFailure := corev1.RestartPolicyOnFailure

	parsedTime, err := time.Parse(certmanager.CertExpiredDateTimeLayout, expiredAt)
	if err != nil {
		return fmt.Errorf("parse expired time err, %v", err)
	}

	expiredTime := parsedTime.AddDate(0, 0, certmanager.DefaultAheadRenewalCertDays)
	schedule := fmt.Sprintf(certmanager.ReDownloadCertCronJobScheduleFormat,
		expiredTime.Minute(), expiredTime.Hour(), expiredTime.Day(), int(expiredTime.Month()))

	cronjob := applyBatchv1.CronJob(certmanager.ReDownloadCertCronJobName, constants.Namespace)
	cronjob.Spec = &applyBatchv1.CronJobSpecApplyConfiguration{
		ConcurrencyPolicy:       &forbidConcurrent,
		Schedule:                pointer.String(schedule),
		StartingDeadlineSeconds: pointer.Int64(3),
	}

	cronjob.Spec.JobTemplate = applyBatchv1.JobTemplateSpec()
	cronjob.Spec.JobTemplate.Spec = applyBatchv1.JobSpec()
	cronjob.Spec.JobTemplate.Spec.Template = applyCorev1.PodTemplateSpec()
	cronjob.Spec.JobTemplate.Spec.Template.Spec = applyCorev1.PodSpec()
	cronjob.Spec.JobTemplate.Spec.Template.Spec.RestartPolicy = &restartOnFailure
	cronjob.Spec.JobTemplate.Spec.Template.Spec.Containers = []applyCorev1.ContainerApplyConfiguration{
		{
			Name:  pointer.String("trigger"),
			Image: pointer.String("busybox:1.28"),
			Command: []string{
				"wget",
				"--header",
				"X-FROM-CRONJOB: true",
				"-qSO - ",
				fmt.Sprintf(certmanager.ReDownloadCertificateAPIFormat, constants.Namespace),
			},
		},
	}

	result, err := t.kubeClient.Kubernetes().BatchV1().CronJobs(constants.Namespace).Apply(t.ctx, cronjob,
		metav1.ApplyOptions{FieldManager: constants.ApplyPatchFieldManager})
	if err != nil {
		return err
	}

	log.Infof("applied %q cronjob: %s", certmanager.ReDownloadCertCronJobName, utils.PrettyJSON(result))

	return nil
}

func (t *EnableHTTPSTask) generateDownloadCert() (*certmanager.ResponseCert, error) {
	var err error
	if err = t.cm.GenerateCert(); err != nil {
		return nil, err
	}

	var c *certmanager.ResponseCert
	if c, err = t.cm.DownloadCert(); err != nil {
		return nil, err
	}

	// create cronjob at expired
	if err = t.newApplyDownloadCertCronJob(c.ExpiredAt); err != nil {
		return nil, err
	}
	return c, nil
}

func (t *EnableHTTPSTask) newApplyConfigMap(c *certmanager.ResponseCert) *applyCorev1.ConfigMapApplyConfiguration {
	// to apply configmap
	return &applyCorev1.ConfigMapApplyConfiguration{
		TypeMetaApplyConfiguration: applyMetav1.TypeMetaApplyConfiguration{
			Kind:       pointer.String("ConfigMap"),
			APIVersion: pointer.String(corev1.SchemeGroupVersion.String()),
		},
		ObjectMetaApplyConfiguration: &applyMetav1.ObjectMetaApplyConfiguration{
			Name:      pointer.String(constants.NameSSLConfigMapName),
			Namespace: pointer.String(constants.Namespace),
		},
		Data: map[string]string{
			"zone":       c.Zone,
			"cert":       c.Cert,
			"key":        c.Key,
			"expired_at": c.ExpiredAt,
		},
	}

}

func (t *EnableHTTPSTask) Execute() {
	var taskResult TaskResult

	var nameCertConfigMap *corev1.ConfigMap

	nameCertConfigMap, err := func() (createdCm *corev1.ConfigMap, err error) {
		// check global l4 proxy or frp agent is ready
		taskResult.State = CheckL4Proxy
		t.UpdateTaskState(taskResult)
		if !t.waitForDeploymentReady(t.o.L4ProxyDeploymentName, t.o.L4ProxyNamespace, t.o.L4ProxyDeploymentReplicas) {
			err = fmt.Errorf("%q still not ready", t.o.L4ProxyDeploymentName)
			return
		}

		if t.o.ReverseProxyEnable {
			taskResult.State = CheckReverseProxyAgent
			t.UpdateTaskState(taskResult)
			if !t.waitForDeploymentReady(t.o.ReverseProxyAgentDeploymentName, t.o.ReverseProxyAgentNamespace, t.o.ReverseProxyAgentDeploymentReplicas) {
				err = fmt.Errorf("%q still not ready", t.o.ReverseProxyAgentDeploymentName)
				return
			}
		}

		// download ssl cert
		taskResult.State = GenerateCert
		t.UpdateTaskState(taskResult)

		var c *certmanager.ResponseCert
		c, err = t.generateDownloadCert()
		if err != nil {
			err = fmt.Errorf("generate cert err, %v", err)
			return
		}

		if err = t.updateUserAnnotation(c.Zone); err != nil {
			err = fmt.Errorf("update user annotaion err, %v", err)
			return
		}

		// configure ingress https
		taskResult.State = ConfigureIngressHTTPs
		t.UpdateTaskState(taskResult)

		createdCm, err = t.kubeClient.Kubernetes().CoreV1().ConfigMaps(constants.Namespace).
			Apply(t.ctx, t.newApplyConfigMap(c), metav1.ApplyOptions{FieldManager: constants.ApplyPatchFieldManager})
		if err != nil {
			err = fmt.Errorf("create ssl cert configmap err: %v", err)
			return
		}

		return
	}()

	if err != nil {
		taskResult.State = Failed
		taskResult.Err = err.Error()
	} else {
		if nameCertConfigMap != nil {
			taskResult.State = Succeeded
			taskResult.Err = ""
			log.Infow("zone ssl config", "data", nameCertConfigMap.Data)
		}
	}

	log.Infow("finished enable ssl", "taskResult", taskResult)

	if err = t.UpdateTaskState(taskResult); err != nil {
		log.Errorf("failed to update task state: %v", err)
	}
}
