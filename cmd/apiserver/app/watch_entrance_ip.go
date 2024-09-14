package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"bytetrade.io/web3os/bfl/internal/log"
	"bytetrade.io/web3os/bfl/pkg/apis/iam/v1alpha1/operator"
	"bytetrade.io/web3os/bfl/pkg/apis/settings/v1alpha1"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils"
	"bytetrade.io/web3os/bfl/pkg/utils/certmanager"
	"bytetrade.io/web3os/bfl/pkg/utils/k8sutil"
	"github.com/emicklei/go-restful"
	"github.com/go-resty/resty/v2"
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
	return reconcile(ctx, constants.TerminusName(terminusName), zone, op, user)
}

func reconcile(ctx context.Context, terminusName constants.TerminusName, zone string, op *operator.UserOperator, user *iamV1alpha2.User) (err error) {
	var (
		isPublicIP                                  bool
		isCloudFlareTunnel                          bool
		publicDomainIp, localDomainIp, natGatewayIp string
	)
	switch reverseProxyType := op.GetUserAnnotation(user, constants.UserAnnotationReverseProxyType); reverseProxyType {
	case "":
		log.Warnf("user %q's network is not set up yet", user.Name)
		return nil
	case constants.ReverseProxyTypeNone:
		isPublicIP = true
	case constants.ReverseProxyTypeCloudflare:
		isCloudFlareTunnel = true
	}

	publicDomainIp = op.GetUserAnnotation(user, constants.UserAnnotationPublicDomainIp)
	localDomainIp = op.GetUserAnnotation(user, constants.UserAnnotationLocalDomainIp)
	if localDomainIp == "" {
		log.Warnf("user %q no local domain ip", user.Name)
		return
	}

	natGatewayIp = op.GetUserAnnotation(user, constants.UserAnnotationNatGatewayIp)

	cm := certmanager.NewCertManager(terminusName)

	var userPatches []func(*iamV1alpha2.User)
	if isPublicIP {
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

	// nat gateway ip
	if natGatewayIp != "" && !isCurrentLocalDomainName(zone, natGatewayIp) {
		err := cm.AddDNSRecord(nil, &natGatewayIp, nil)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// local ip
	newLocalIp, err := k8sutil.GetL4ProxyNodeIP(ctx, 5*time.Minute)
	if err != nil {
		return err
	}

	if newLocalIp != nil &&
		*newLocalIp != "127.0.0.1" && *newLocalIp != "127.0.1.1" &&
		localDomainIp != *newLocalIp {
		log.Debugf("original local node ip: %s", localDomainIp)

		// resolve local domain
		if natGatewayIp == "" {
			// non-nat mode
			err := cm.AddDNSRecord(nil, newLocalIp, nil)
			if err != nil {
				return errors.WithStack(err)
			}
		}
		userPatches = append(userPatches, func(u *iamV1alpha2.User) {
			u.Annotations[constants.UserAnnotationLocalDomainIp] = *newLocalIp
		})

		if err = op.UpdateUser(user, userPatches); err != nil {
			return errors.WithStack(err)
		}

		log.Infof("resolved new local ip: %s", *newLocalIp)

		if isCloudFlareTunnel {
			// get cloudflare token
			jws := user.Annotations[constants.UserCertManagerJWSToken]
			if jws == "" {
				return errors.Errorf("enable https: user jws not found")
			}

			terminusName := user.Annotations[constants.UserAnnotationTerminusNameKey]
			req := v1alpha1.TunnelRequest{
				Name:    terminusName,
				Service: fmt.Sprintf("https://%s:%s", *newLocalIp, "443"),
			}

			res, err := resty.New().SetTimeout(30 * time.Second).
				SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).R().
				SetHeaders(map[string]string{
					restful.HEADER_ContentType: restful.MIME_JSON,
					restful.HEADER_Accept:      restful.MIME_JSON,
					"Authorization":            "Bearer " + jws,
				}).
				SetBody(req).
				SetResult(&v1alpha1.TunnelResponse{}).
				Post("https://terminus-dnsop.snowinning.com/tunnel")

			if err != nil {
				log.Error("request cloudflare tunnel api error, ", err)
				return err
			}

			if res.StatusCode() != http.StatusOK {
				err = errors.New(string(res.Body()))
				return err
			}

			responseData := res.Result().(*v1alpha1.TunnelResponse)
			if !responseData.Success || responseData.Data == nil || responseData.Data.Token == "" {
				log.Errorf("get cloudflare tunnel token failed, %v", responseData)
				err = errors.Errorf("enable https: get cloudflare tunnel token failed")
				return err
			}
		} // end of cloudflare tunnel
	}

	return
}

func isCurrentLocalDomainName(terminusName, ip string) bool {
	domain := "local." + terminusName

	ips, err := net.LookupIP(domain)
	if err != nil {
		log.Errorf("lookup domain failed, %v, %v", err, domain)
		return true
	}

	for _, i := range ips {
		if i.To4().String() == ip {
			return true
		}
	}

	return false
}
