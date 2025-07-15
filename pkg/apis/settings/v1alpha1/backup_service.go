package v1alpha1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"bytetrade.io/web3os/bfl/internal/log"
	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils"

	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Method string

func (m Method) String() string {
	return string(m)
}

const (
	GET    Method = "GET"
	POST          = "POST"
	PUT           = "PUT"
	DELETE        = "DELETE"
	PATCH         = "PATCH"
)

var (
	available = "available"
	plans     = "plans"
	plan      = "plan"
	snapshots = "snapshots"
	snapshot  = "snapshot"

	backupHTTPDefaultTimeout = 5 * time.Second
	backupAPIVersion         = "v1"
	backupAPIs               = map[string]string{
		available: "/available",
		plans:     "/plans",
		plan:      "/plans/%s",
		snapshots: "/plans/%s/snapshots?limit=%s",
		snapshot:  "/plans/%s/snapshots/%s",
	}
)

type BackupService struct {
	httpClient *http.Client
	apiPrefix  string
	apiVersion string

	apis map[string]string
}

func NewBackupService() *BackupService {
	addr := utils.EnvOrDefault("BACKUP_SERVER", "backup-server.os-framework:8082")

	addr = strings.TrimRight(addr, "/")
	apiPrefix := fmt.Sprintf("http://%s/apis/backup/%s", addr, backupAPIVersion)

	bs := BackupService{
		apiPrefix:  apiPrefix,
		httpClient: &http.Client{Timeout: backupHTTPDefaultTimeout},
	}
	bs.apis = backupAPIs

	return &bs
}

func (b *BackupService) buildRequestURL(name string, params ...any) string {
	return b.apiPrefix + fmt.Sprintf(b.apis[name], params...)
}

func (b *BackupService) Available() (any, error) {
	return b.request(GET, b.buildRequestURL("available"), nil)
}

func (b *BackupService) IsAdminUser(ctx context.Context) (bool, error) {
	kc, err := runtime.NewKubeClientInCluster()
	if err != nil {
		return false, err
	}

	user, err := kc.KubeSphere().IamV1alpha2().Users().Get(ctx, constants.Username, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	role, ok := user.Annotations[constants.UserAnnotationOwnerRole]
	if !ok {
		return false, errors.Errorf("invalid user %q, no owner role annotation", user.Name)
	}
	return role == constants.RoleOwner || role == constants.RoleAdmin, nil
}

func (b *BackupService) CreatePlan(data any) (any, error) {
	return b.request(POST, b.buildRequestURL(plans), data)
}

func (b *BackupService) ListPlans() (any, error) {
	return b.request(GET, b.buildRequestURL(plans), nil)
}

func (b *BackupService) DescribePlan(name string) (any, error) {
	return b.request(GET, b.buildRequestURL(plan, name), nil)
}

func (b *BackupService) UpdatePlan(name string, data any) (any, error) {
	return b.request(PUT, b.buildRequestURL(plan, name), data)
}

func (b *BackupService) DeletePlan(name string) (any, error) {
	return b.request(DELETE, b.buildRequestURL(plan, name), nil)
}

func (b *BackupService) ListSnapshots(plan, limit string) (any, error) {
	return b.request(GET, b.buildRequestURL(snapshots, plan, limit), nil)
}

func (b *BackupService) DescribeSnapshot(plan, name string) (any, error) {
	return b.request(GET, b.buildRequestURL(snapshot, plan, name), nil)
}

func (b *BackupService) DeleteSnapshot(plan, name string) (any, error) {
	return b.request(DELETE, b.buildRequestURL(snapshot, plan, name), nil)
}

func (b *BackupService) request(method Method, url string, body any) (any, error) {
	var (
		err      error
		reqBytes []byte
		br       io.Reader
		req      *http.Request
	)

	if body != nil {
		reqBytes, err = json.Marshal(body)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		br = bytes.NewReader(reqBytes)
	}

	req, err = http.NewRequest(method.String(), url, br)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	req.Header.Set("X-Backup-Owner", constants.Username)
	req.Header.Set("Accept", "application/json")
	if utils.ListContains([]Method{POST, PUT, PATCH}, method) && body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	log.Debugw("requesting backup api",
		"reqURL", url,
		"method", method,
		"headers", req.Header,
		"reqBody", string(reqBytes),
	)

	var resp *http.Response
	resp, err = b.httpClient.Do(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var respBytes []byte

	respBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer resp.Body.Close()

	log.Debugf("response code: %v, body: %v", resp.StatusCode, string(respBytes))

	if resp.StatusCode != http.StatusOK {
		log.Warnf("unexpected http code: %v", resp.StatusCode)
	}

	// check response
	var r response.Response
	if err = json.Unmarshal(respBytes, &r); err != nil {
		return nil, errors.WithStack(err)
	}

	if r.Code != 0 && r.Message != "" {
		return nil, errors.New(r.Message)
	}

	return r.Data, nil
}
