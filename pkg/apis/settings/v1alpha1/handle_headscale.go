package v1alpha1

import (
	"context"
	"errors"
	"slices"
	"strings"

	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/client/dynamic_client"
	"bytetrade.io/web3os/bfl/pkg/client/dynamic_client/apps"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"github.com/emicklei/go-restful/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	"k8s.io/klog/v2"
)

type AclState string

const (
	AclStateApplying AclState = "applying"
	AclStateApplied  AclState = "applied"

	ENV_HEADSCALE_ACL_SSH = "HEADSCALE_ACL_SSH"
)

type SshAcl struct {
	AllowSSH bool     `json:"allow_ssh"`
	State    AclState `json:"state"`
}

type Acl struct {
	Proto string   `json:"proto"`
	Dst   []string `json:"Dst"`
}

// settings' acl

func (h *Handler) handleGetHeadscaleSshAcl(req *restful.Request, resp *restful.Response) {
	app, err := h.findApp(req.Request.Context(), "settings")
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	// get headscale acl env
	allowSSH := false
	for _, acl := range app.Spec.TailScaleACLs {
		if slices.Contains(acl.Dst, "*:22") && strings.ToLower(acl.Proto) == "tcp" {
			allowSSH = true
			break
		}
	}

	response.Success(resp, SshAcl{AllowSSH: allowSSH, State: AclStateApplied})
}

func (h *Handler) handleDisableHeadscaleSshAcl(req *restful.Request, resp *restful.Response) {
	h.setHeadscaleAcl(req, resp, "settings", nil)
}

func (h *Handler) handleEnableHeadscaleSshAcl(req *restful.Request, resp *restful.Response) {
	h.setHeadscaleAcl(req, resp, "settings", []apps.ACL{
		{Proto: "tcp", Dst: []string{"*:22"}},
	})
}

// app's acl

func (h *Handler) handleGetHeadscaleAppAcl(req *restful.Request, resp *restful.Response) {
	appName := req.PathParameter(ParamAppName)

	app, err := h.findApp(req.Request.Context(), appName)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	var acls []Acl
	for _, acl := range app.Spec.TailScaleACLs {
		acls = append(acls, Acl{
			Proto: acl.Proto,
			Dst:   acl.Dst,
		})
	}

	response.Success(resp, acls)
}

func (h *Handler) handleUpdateHeadscaleAppAcl(req *restful.Request, resp *restful.Response) {
	appName := req.PathParameter(ParamAppName)
	acls, err := h.parseAcl(req)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	h.setHeadscaleAcl(req, resp, appName, acls)
}

func (h *Handler) setHeadscaleAcl(req *restful.Request, resp *restful.Response, appName string, acls []apps.ACL) {

	app, err := h.findApp(req.Request.Context(), appName)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		app.Spec.TailScaleACLs = acls
		return nil
	})

	if err != nil {
		klog.Error("Failed to update headscale acl: ", err)
		response.HandleError(resp, err)
		return
	}

	response.SuccessNoData(resp)
}

func (h *Handler) findApp(ctx context.Context, appName string) (*apps.Application, error) {
	client, err := dynamic_client.NewResourceClient[apps.Application, apps.ApplicationList](apps.ApplicationGvr)
	if err != nil {
		klog.Error("failed to get client: ", err)
		return nil, err
	}

	apps, err := client.List(ctx, metav1.ListOptions{})
	if err != nil {
		klog.Error("list app error: ", err)
		return nil, err
	}

	for _, a := range apps {
		if a.Spec.Name == appName && a.Spec.Owner == constants.Username {
			return &a, nil
		}
	}

	return nil, errors.New("app not found")
}

func (h *Handler) parseAcl(req *restful.Request) ([]apps.ACL, error) {
	var acls []apps.ACL
	err := req.ReadEntity(&acls)
	if err != nil {
		klog.Error("parse request acl body error, ", err)
		return nil, err
	}

	for _, a := range acls {
		acls = append(acls, apps.ACL{
			Proto: a.Proto,
			Dst:   a.Dst,
		})
	}

	err = apps.CheckTailScaleACLs(acls)
	if err != nil {
		klog.Error("check acl error, ", err)
		return nil, err
	}

	return acls, nil
}
