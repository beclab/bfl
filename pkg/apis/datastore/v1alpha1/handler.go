package v1alpha1

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"bytetrade.io/web3os/bfl/pkg/api"
	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/apis/datastore/v1alpha1/store"
	"bytetrade.io/web3os/bfl/pkg/constants"

	"github.com/emicklei/go-restful/v3"
	"k8s.io/klog/v2"
)

type Handler struct {
	store store.Store
}

type Filter interface {
	filter(req *restful.Request, resp *restful.Response, chain *restful.FilterChain)
}

// Open a single store
type OpenStore struct {
	Filter
	handler *Handler
}

func (f *OpenStore) filter(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	if !f.handler.openStore(req, resp) {
		return
	}

	chain.ProcessFilter(req, resp)
}

// provider interface
type RequestData struct {
	Key   string                 `json:"key"`
	Value map[string]interface{} `json:"value,omitempty"`
}
type DataStoreProviderRequest struct {
	Op       string      `json:"op"`
	DataType string      `json:"datatype"`
	Version  string      `json:"version"`
	Group    string      `json:"group"`
	AppKey   string      `json:"appkey"`
	Param    interface{} `json:"param,omitempty"`
	Data     RequestData `json:"data,omitempty"`
	Token    string
}

const (
	RequestDataKey = "reqeust-data"
)

type ProviderRequestFilter struct {
	Filter
}

func (f *ProviderRequestFilter) filter(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	var opt DataStoreProviderRequest
	if err := req.ReadEntity(&opt); err != nil {
		response.HandleError(resp, err)
		return
	}

	if opt.DataType != "datastore" || opt.Group != "service.bfl" || opt.Version != "v1" {
		response.HandleError(resp, errors.New("wrong data type"))
		return
	}

	// add app key as namespace
	opt.Data.Key = strings.Join([]string{opt.AppKey, opt.Data.Key}, ":")
	req.SetAttribute(RequestDataKey, &opt.Data)

	chain.ProcessFilter(req, resp)
}

func New() (*Handler, []Filter, error) {
	s, err := store.NewPebbleStore()
	if err != nil {
		return nil, nil, err
	}

	handler := &Handler{store: s}
	filters := []Filter{
		&OpenStore{handler: handler},
		&ProviderRequestFilter{},
	}
	return handler, filters, nil
}

// TODO: response OK msg
type OK struct {
	Code int `json:"code"`
}

func (h *Handler) openStore(request *restful.Request, resp *restful.Response) bool {
	user := constants.Username
	if user == "" {
		response.HandleError(resp, fmt.Errorf("open store: user context is empty"))
		return false
	}

	if err := h.store.Open(user); err != nil {
		response.HandleError(resp, err)
		return false
	}
	return true
}

func (h *Handler) handleGetKey(request *restful.Request, resp *restful.Response) {
	param, ok := request.Attribute(RequestDataKey).(*RequestData)
	if !ok {
		response.HandleError(resp, errors.New("request data field invalid"))
		return
	}

	key := []byte(param.Key)

	klog.Info("get key: ", param.Key)
	value, err := h.store.Get(key)
	if err != nil {
		// if not found, 404 will be returned
		if err == store.ErrKeyNotFound {
			response.HandleNotFound(resp, fmt.Errorf("get key: %v", err))
			return
		}

		response.HandleError(resp, fmt.Errorf("get key: %v", err))
		return
	}

	response.Success(resp, json.RawMessage(value))
}

func (h *Handler) handleGetKeyPrefix(request *restful.Request, resp *restful.Response) {
	param, ok := request.Attribute(RequestDataKey).(*RequestData)
	if !ok {
		response.HandleError(resp, errors.New("request data field invalid"))
		return
	}

	keyPrefix := []byte(param.Key)

	klog.Info("get key prefix: ", param.Key)
	values, err := h.store.MGet(keyPrefix)
	for i, v := range values {
		// strip app key namespace
		values[i].Key = strings.Join(strings.Split(v.Key, ":")[:1], ":")
	}

	if err != nil {
		response.HandleError(resp, fmt.Errorf("get key prefix: %v", err))
		return
	}
	response.Success(resp, api.NewListResult(values))
}

func (h *Handler) handleSet(request *restful.Request, resp *restful.Response) {
	param, ok := request.Attribute(RequestDataKey).(*RequestData)
	if !ok {
		response.HandleError(resp, errors.New("request data field invalid"))
		return
	}

	key := []byte(param.Key)

	klog.Info("set key: ", param.Key)
	value, err := json.Marshal(param.Value)
	if err != nil {
		response.HandleError(resp, fmt.Errorf("set data: %v", err))
		return
	}

	if err := h.store.Set(key, json.RawMessage(value)); err != nil {
		response.HandleError(resp, fmt.Errorf("set data: %v", err))
		return
	}
	response.SuccessNoData(resp)
}

func (h *Handler) handleDelete(request *restful.Request, resp *restful.Response) {
	param, ok := request.Attribute(RequestDataKey).(*RequestData)
	if !ok {
		response.HandleError(resp, errors.New("request data field invalid"))
		return
	}

	key := []byte(param.Key)

	klog.Info("delete key: ", param.Key)
	err := h.store.Delete(key)
	if err != nil {
		response.HandleError(resp, fmt.Errorf("delete key: %v", err))
		return
	}
	response.SuccessNoData(resp)
}
