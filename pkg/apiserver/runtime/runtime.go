package runtime

import (
	"fmt"

	v1alpha1client "bytetrade.io/web3os/bfl/pkg/client/clientset/v1alpha1"
	"bytetrade.io/web3os/bfl/pkg/constants"

	"github.com/emicklei/go-restful/v3"
	"github.com/form3tech-oss/jwt-go"
	"k8s.io/client-go/rest"
	kubejwt "kubesphere.io/kubesphere/pkg/apiserver/authentication/token"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	APIRootPath = "/bfl"
)

type ModuleVersion struct {
	Name    string
	Version string
}

func NewWebService(mv ModuleVersion) *restful.WebService {
	webservice := restful.WebService{}

	webservice.Path(fmt.Sprintf("%s/%s/%s", APIRootPath, mv.Name, mv.Version)).
		Produces(restful.MIME_JSON)

	return &webservice
}

func NewKubeClientInCluster() (v1alpha1client.Client, error) {
	config, err := ctrl.GetConfig()
	if err != nil {
		return nil, err
	}

	c, err := v1alpha1client.NewKubeClient(config)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func NewKubeClient(req *restful.Request) v1alpha1client.Client {
	config := rest.Config{
		Host:        constants.KubeSphereAPIHost,
		BearerToken: req.HeaderParameter(constants.AuthorizationTokenKey),
	}
	return v1alpha1client.NewKubeClientOrDie("", &config)
}

func NewKubeClientWithToken(token string) v1alpha1client.Client {
	config := rest.Config{
		Host:        constants.KubeSphereAPIHost,
		BearerToken: token,
	}
	return v1alpha1client.NewKubeClientOrDie("", &config)
}

func ParseToken(tokenStr string) (*kubejwt.Claims, error) {
	if tokenStr == "" {
		return nil, fmt.Errorf("parse token err, empty token string")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &kubejwt.Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return constants.KubeSphereJwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*kubejwt.Claims)
	if ok && token.Valid && claims.Username != "" {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token, or claims not match")
}
