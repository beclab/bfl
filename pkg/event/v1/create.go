package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful/v3"
)

func (c *Client) CreateEvent(eventType string, msg string, data interface{}) error {
	url := fmt.Sprintf("http://%s/system-server/v1alpha1/event/message-disptahcer.system-server/v1", eventServer)
	token, err := c.getAccessToken()
	if err != nil {
		return err
	}

	event := Event{
		Type:    eventType,
		Version: EventVersion,
		Data: EventData{
			Message: msg,
			Payload: data,
		},
	}

	postData, err := json.Marshal(event)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.R().
		SetHeaders(map[string]string{
			restful.HEADER_ContentType: restful.MIME_JSON,
			AccessTokenHeader:          token,
		}).
		SetResult(&Response{}).
		SetBody(postData).
		Post(url)

	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusOK {
		return errors.New(string(resp.Body()))
	}

	responseData := resp.Result().(*Response)

	if responseData.Code != 0 {
		return errors.New(responseData.Message)
	}

	return nil
}
