package v1alpha1

type InstallationResponse struct {
	UID string `json:"uid"`
}

type InstallationStatusResp struct {
	UID    string `json:"uid"`
	Status string `json:"status"`
}
