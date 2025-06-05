package analytics

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/go-resty/resty/v2"
	"k8s.io/klog/v2"
)

type Request struct {
	Name  string `json:"name"`
	AppID string `json:"appId"`
}

type Response struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Domain    string    `json:"domain"`
	ShareID   string    `json:"shareId"`
	ResetAt   time.Time `json:"resetAt"`
	UserID    string    `json:"userId"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	DeletedAt time.Time `json:"deletedAt"`
}

type Client struct {
	client *resty.Client
}

func NewClient() *Client {
	client := resty.New()
	client.SetRetryCount(3)
	client.SetRetryWaitTime(1 * time.Second)
	return &Client{
		client: client,
	}
}

func (a *Client) GetAnalyticsID(appName string, appId string, ownerName string) (*Response, error) {
	req := Request{
		Name: appName,
	}
	url := "http://analytics-server.os-system:3010/api/websites"

	resp, err := a.client.R().
		SetHeader(restful.HEADER_ContentType, restful.MIME_JSON).
		SetHeader("x-bfl-user", ownerName).
		SetBody(req).Post(url)
	if err != nil {
		klog.Info("get analytics id error, ", err)
		return nil, err
	}
	if resp.StatusCode() != 200 {
		klog.Info("get analytics id  error, ", resp.Status())
		return nil, errors.New(resp.Status())
	}
	var analyticsResp Response
	err = json.Unmarshal(resp.Body(), &analyticsResp)
	if err != nil {
		klog.Info("get analytics id response error, ", err)
		return nil, err
	}

	return &analyticsResp, nil
}
