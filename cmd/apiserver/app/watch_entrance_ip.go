package app

import (
	"context"
	"time"

	"bytetrade.io/web3os/bfl/internal/log"
	"bytetrade.io/web3os/bfl/pkg/apis/iam/v1alpha1/operator"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils"
	"bytetrade.io/web3os/bfl/pkg/utils/certmanager"
	"bytetrade.io/web3os/bfl/pkg/utils/k8sutil"
	"github.com/pkg/errors"
	iamV1alpha2 "kubesphere.io/api/iam/v1alpha2"
)

func watchEntranceIP() {
	ctx := context.Background()

	if err := watch(ctx); err != nil {
		log.Errorf("%+v", err)
	}
}

func watch(ctx context.Context) (err error) {
	var (
		op                 *operator.UserOperator
		user               *iamV1alpha2.User
		terminusName, zone string
	)

	op, err = operator.NewUserOperator()
	if err != nil {
		return errors.WithStack(err)
	}
	user, err = op.GetUser("")
	if err != nil {
		return errors.WithStack(err)
	}

	terminusName = op.GetUserAnnotation(user, constants.UserAnnotationTerminusNameKey)
	if terminusName == "" {
		log.Warnf("user %q terminus name not binding yet", user.Name)
		return
	}
	zone = op.GetUserAnnotation(user, constants.UserAnnotationZoneKey)
	if zone == "" {
		log.Warnf("user %q not enabled https", user.Name)
		return
	}

	// reconcile dns record
	return reconcile(ctx, constants.TerminusName(terminusName), op, user)
}

func reconcile(ctx context.Context, terminusName constants.TerminusName, op *operator.UserOperator, user *iamV1alpha2.User) (err error) {
	var (
		isFrp                         bool
		publicDomainIp, localDomainIp string
	)

	publicDomainIp = op.GetUserAnnotation(user, constants.UserAnnotationPublicDomainIp)
	if publicDomainIp != "" {
		if utils.ListContains(constants.FrpServers, publicDomainIp) {
			isFrp = true
		}
	}

	localDomainIp = op.GetUserAnnotation(user, constants.UserAnnotationLocalDomainIp)
	if localDomainIp == "" {
		log.Warnf("user %q no local domain ip", user.Name)
		return
	}

	cm := certmanager.NewCertManager(terminusName)

	var userPatches []func(*iamV1alpha2.User)
	if !isFrp && publicDomainIp != "" {
		// only for public ip
		publicIp := ""
		if role, ok := user.Annotations[constants.UserAnnotationOwnerRole]; ok && role == constants.RolePlatformAdmin {
			publicIp = utils.GetMyExternalIPAddr()
		} else {
			publicIp = *k8sutil.GetMasterExternalIP(ctx)
		}

		if publicIp == "" {
			return errors.New("no public ip found")
		}
		log.Debugf("got current public ip: %s", publicIp)

		if publicIp == publicDomainIp {
			log.Info("public ip no changed")
			return nil
		}
		if err = cm.AddDNSRecord(&publicIp, nil, nil); err != nil {
			return errors.WithStack(err)
		}
		userPatches = append(userPatches, func(u *iamV1alpha2.User) {
			u.Annotations[constants.UserAnnotationPublicDomainIp] = publicIp
		})
		log.Infof("resolved new public ip: %v", publicIp)
	}

	// local ip
	newLocalIp, err := k8sutil.GetL4ProxyNodeIP(ctx, 5*time.Minute)
	if err != nil {
		return err
	}

	if newLocalIp != nil && localDomainIp != *newLocalIp {
		log.Debugf("original local node ip: %s", localDomainIp)

		// resolve local domain
		err := cm.AddDNSRecord(nil, newLocalIp, nil)
		if err != nil {
			return errors.WithStack(err)
		}
		userPatches = append(userPatches, func(u *iamV1alpha2.User) {
			u.Annotations[constants.UserAnnotationLocalDomainIp] = *newLocalIp
		})
		log.Infof("resolved new local ip: %s", *newLocalIp)
	}

	if err = op.UpdateUser(user, userPatches); err != nil {
		return errors.WithStack(err)
	}

	return
}
