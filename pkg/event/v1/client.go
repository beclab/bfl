package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/emicklei/go-restful"
	"github.com/go-resty/resty/v2"
	"golang.org/x/crypto/bcrypt"
)

var (
	appKey      = ""
	appSecret   = ""
	eventServer = ""
)

func init() {
	appKey = os.Getenv("OS_APP_KEY")
	appSecret = os.Getenv("OS_APP_SECRET")
	eventServer = os.Getenv("OS_SYSTEM_SERVER")
}

const (
	GroupID           = "message-disptahcer.system-server"
	EventVersion      = "v1"
	AccessTokenHeader = "X-Access-Token"
)

type Client struct {
	httpClient *resty.Client
}

func NewClient() *Client {
	c := resty.New()

	return &Client{
		httpClient: c.SetTimeout(2 * time.Second),
	}
}

func (c *Client) getAccessToken() (string, error) {
	url := fmt.Sprintf("http://%s/permission/v1alpha1/access", eventServer)
	now := time.Now().UnixMilli() / 1000

	password := appKey + strconv.Itoa(int(now)) + appSecret
	encode, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	perm := AccessTokenRequest{
		AppKey:    appKey,
		Timestamp: now,
		Token:     string(encode),
		Perm: PermissionRequire{
			Group:    GroupID,
			Version:  EventVersion,
			DataType: "event",
			Ops: []string{
				"Create",
			},
		},
	}

	postData, err := json.Marshal(perm)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.R().
		SetHeader(restful.HEADER_ContentType, restful.MIME_JSON).
		SetBody(postData).
		SetResult(&AccessTokenResp{}).
		Post(url)

	if err != nil {
		return "", err
	}

	if resp.StatusCode() != http.StatusOK {
		return "", errors.New(string(resp.Body()))
	}

	token := resp.Result().(*AccessTokenResp)

	if token.Code != 0 {
		return "", errors.New(token.Message)
	}

	return token.Data.AccessToken, nil
}
