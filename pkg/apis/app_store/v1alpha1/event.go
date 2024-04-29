package v1alpha1

import (
	"context"
	"fmt"
	"time"

	"bytetrade.io/web3os/bfl/pkg/app_service/v1"
	"bytetrade.io/web3os/bfl/pkg/event/v1"

	"k8s.io/klog"
)

type InstallationWatchDog struct {
	client           *event.Client
	uid              string
	ctx              context.Context
	cancel           context.CancelFunc
	op               string
	app              string
	token            string
	appServiceClient *app_service.Client
	clear            func(string)
}

type EventData struct {
	Op     string `json:"op"`
	App    string `json:"app"`
	Uid    string `json:"uid"`
	Status string `json:"status"`
}

const (
	APP_EVENT = "app-installation-event"

	OP_INSTALL   = "install"
	OP_UNINSTALL = "uninstall"

	Installing   = "installing"
	Uninstalling = "uninstalling"
	Completed    = "completed"
	Canceled     = "canceled"
	Failed       = "failed"
)

type OpType string

var (
	Install    OpType = "install"
	Uninstall  OpType = "uninstall"
	Upgrade    OpType = "upgrade"
	SuspendApp OpType = "suspend"
	ResumeApp  OpType = "resume"
	Cancel     OpType = "cancel"
)

func (op OpType) String() string {
	return string(op)
}

type WatchDogManager map[string]*InstallationWatchDog

func NewWatchDogManager() WatchDogManager {
	return make(WatchDogManager)
}

func (w WatchDogManager) NewWatchDog(installOp, appname, uid, token string, client *app_service.Client) *InstallationWatchDog {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)

	eventClient := event.NewClient()

	wd := &InstallationWatchDog{
		client:           eventClient,
		uid:              uid,
		ctx:              ctx,
		cancel:           cancel,
		op:               installOp,
		app:              appname,
		token:            token,
		appServiceClient: client,
		clear:            w.DeleteWatchDog,
	}
	w[uid] = wd

	return wd
}

func (w WatchDogManager) CancelWatchDog(uid string) {
	if wd, ok := w[uid]; ok {
		wd.cancel()
		w.DeleteWatchDog(uid)
	}
}

func (w WatchDogManager) DeleteWatchDog(uid string) {
	delete(w, uid)
}

func (i *InstallationWatchDog) Exec() {
	ticker := time.NewTicker(5 * time.Second)

	defer func() {
		ticker.Stop()
		i.clear(i.uid)
	}()

	s, m := i.statusDoing()
	data := i.genEvent(s)

	// start watch dog, send the first event of the action beginning
	err := i.client.CreateEvent(APP_EVENT, m, &data)
	if err != nil {
		klog.Error("send app installation event error, ", i.app, ", ", i.uid, ", ", err)
		return
	}

	for {
		select {

		case <-i.ctx.Done(): // timeout or canceled
			status, msg, opType, err := i.getStatus()
			if err != nil {
				klog.Error("get installation status err, ", i.app, ", ", i.uid, ", ", err)
			}

			if opType == Cancel.String() {
				err = i.cancelOp()
				if err != nil {
					klog.Error("Cancel installation err,", i.app, ", ", i.uid, ", ", err)
				}

				data := i.genEvent(Canceled)
				err = i.client.CreateEvent(APP_EVENT, i.statusCanceled(), &data)
				if err != nil {
					klog.Error("send app installation event error, ", i.app, ", ", i.uid, ", ", err)
				}
				return
			}
			if status == Completed {
				data := i.genEvent(Completed)
				err = i.client.CreateEvent(APP_EVENT, i.statusComplete(), &data)
				if err != nil {
					klog.Error("send app installation event error, ", i.app, ", ", i.uid, ", ", err)
				}
				return
			}
			if status == Failed {
				data := i.genEvent(Failed)
				err = i.client.CreateEvent(APP_EVENT, i.statusFail(msg), &data)
				if err != nil {
					klog.Error("send app installation event error, ", i.app, ", ", i.uid, ", ", err)
				}
				return

			}
			return

		case <-ticker.C:
			status, msg, _, err := i.getStatus()
			if err != nil {
				klog.Error("get installation status err, ", i.app, ", ", i.uid, ", ", err)
			}
			if status == Completed {
				data := i.genEvent(Completed)
				err = i.client.CreateEvent(APP_EVENT, i.statusComplete(), &data)
				if err != nil {
					klog.Error("send app installation event error, ", i.app, ", ", i.uid, ", ", err)
				} else {
					return
				}
			} else if status == Failed {
				data := i.genEvent(Failed)
				err = i.client.CreateEvent(APP_EVENT, i.statusFail(msg), &data)
				if err != nil {
					klog.Error("send app installation event error, ", i.app, ", ", i.uid, ", ", err)
				} else {
					return
				}
			}
		}
	}
}

func (i *InstallationWatchDog) statusDoing() (string, string) {
	switch i.op {
	case OP_INSTALL:
		return "installing", fmt.Sprintf("%s started to install", i.app)
	case OP_UNINSTALL:
		return "uninstalling", fmt.Sprintf("%s started to uninstall", i.app)
	}

	return "unknown", ""
}

func (i *InstallationWatchDog) statusFail(err string) string {
	switch i.op {
	case OP_INSTALL:
		return fmt.Sprintf("%s's installation fail, it has been canceled. Err: %s", i.app, err)
	case OP_UNINSTALL:
		return fmt.Sprintf("%s's uninstallation fail, it has been canceled. Err: %s", i.app, err)
	}

	return "unknown"
}

func (i *InstallationWatchDog) statusComplete() string {
	switch i.op {
	case OP_INSTALL:
		return fmt.Sprintf("%s's installation is completed", i.app)
	case OP_UNINSTALL:
		return fmt.Sprintf("%s's uninstallation is completed", i.app)
	}

	return "unknown"
}

func (i *InstallationWatchDog) statusCanceled() string {
	switch i.op {
	case OP_INSTALL:
		return fmt.Sprintf("%s's installation has been canceled", i.app)
	case OP_UNINSTALL:
		return fmt.Sprintf("%s's uninstallation has been canceled", i.app)
	}

	return "unknown"
}

func (i *InstallationWatchDog) getStatus() (string, string, string, error) {
	data, err := i.appServiceClient.AppInstallStatus(i.uid, i.token)
	if err != nil {
		return "", "", "", err
	}

	//statusData := data["data"].(map[string]interface{})
	status := data["state"].(string)
	msg := data["message"].(string)
	opType := data["opType"].(string)
	return status, msg, opType, nil
}

func (i *InstallationWatchDog) cancelOp() error {
	_, err := i.appServiceClient.AppInstallCancel(i.uid, i.token)

	return err

}

func (i *InstallationWatchDog) genEvent(status string) *EventData {
	return &EventData{
		App:    i.app,
		Op:     i.op,
		Uid:    i.uid,
		Status: status,
	}
}
