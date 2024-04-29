package v1alpha1

import (
	"bytetrade.io/web3os/bfl/pkg/api/response"

	"github.com/emicklei/go-restful/v3"
	"github.com/pkg/errors"
)

var errNoPermission = errors.New("Not an administrator, does not have permission to add backups")

func (h *Handler) availableBackupServer(r *restful.Request, w *restful.Response) {
	_, err := h.backupService.Available()
	if err != nil {
		response.HandleError(w, errors.WithMessage(err, "backup server available"))
		return
	}

	response.SuccessNoData(w)
}

func (h *Handler) createBackupPlan(r *restful.Request, w *restful.Response) {
	var (
		err    error
		entity any
		res    any
	)

	if err = r.ReadEntity(&entity); err != nil {
		response.HandleError(w, err)
		return
	}

	isAdmin, err := h.backupService.IsAdminUser(r.Request.Context())
	if err != nil || !isAdmin {
		response.HandleError(w, errNoPermission)
		return
	}

	res, err = h.backupService.CreatePlan(entity)
	if err != nil {
		response.HandleError(w, errors.WithMessage(err, "create plan"))
		return
	}
	response.Success(w, res)
}

func (h *Handler) listBackupPlans(r *restful.Request, w *restful.Response) {
	res, err := h.backupService.ListPlans()
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Success(w, res)
}

func (h *Handler) updateBackupPlan(r *restful.Request, w *restful.Response) {
	name := r.PathParameter("name")

	var (
		err    error
		entity any
		res    any
	)

	if err = r.ReadEntity(&entity); err != nil {
		response.HandleError(w, err)
		return
	}

	isAdmin, err := h.backupService.IsAdminUser(r.Request.Context())
	if err != nil || !isAdmin {
		response.HandleError(w, errNoPermission)
		return
	}

	res, err = h.backupService.UpdatePlan(name, entity)
	if err != nil {
		response.HandleError(w, errors.WithMessage(err, "update plan"))
		return
	}
	response.Success(w, res)
}

func (h *Handler) describeBackupPlan(r *restful.Request, w *restful.Response) {
	name := r.PathParameter("name")

	res, err := h.backupService.DescribePlan(name)
	if err != nil {
		response.HandleError(w, errors.WithMessage(err, "describe plan"))
		return
	}

	response.Success(w, res)
}

func (h *Handler) deleteBackupPlan(r *restful.Request, w *restful.Response) {
	name := r.PathParameter("name")

	res, err := h.backupService.DeletePlan(name)
	if err != nil {
		response.HandleError(w, errors.WithMessage(err, "delete plan"))
		return
	}

	response.Success(w, res)
}

func (h *Handler) listBackupSnapshots(r *restful.Request, w *restful.Response) {
	limit := r.QueryParameter("limit")
	planName := r.PathParameter("plan_name")

	if limit == "" {
		limit = "10"
	}

	res, err := h.backupService.ListSnapshots(planName, limit)
	if err != nil {
		response.HandleError(w, errors.WithMessage(err, "list backup snapshots"))
		return
	}
	response.Success(w, res)
}

func (h *Handler) describeBackupSnapshot(r *restful.Request, w *restful.Response) {
	name := r.PathParameter("name")
	planName := r.PathParameter("plan_name")

	res, err := h.backupService.DescribeSnapshot(planName, name)
	if err != nil {
		response.HandleError(w, errors.WithMessage(err, "descirbe backup snapshot"))
		return
	}
	response.Success(w, res)
}

func (h *Handler) deleteBackupSnapshot(r *restful.Request, w *restful.Response) {
	name := r.PathParameter("name")
	planName := r.PathParameter("plan_name")

	res, err := h.backupService.DeleteSnapshot(planName, name)
	if err != nil {
		response.HandleError(w, errors.WithMessage(err, "delete snapshot"))
		return
	}
	response.Success(w, res)
}
