package apiserver

import (
	"bytes"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"bytetrade.io/web3os/bfl/internal/log"
	"bytetrade.io/web3os/bfl/pkg/api/response"
	apiRuntime "bytetrade.io/web3os/bfl/pkg/apiserver/runtime"
	"bytetrade.io/web3os/bfl/pkg/constants"
	"bytetrade.io/web3os/bfl/pkg/utils"

	"github.com/emicklei/go-restful/v3"
)

func logStackOnRecover(panicReason interface{}, w http.ResponseWriter) {
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("recover from panic situation: - %v\r\n", panicReason))
	for i := 2; ; i += 1 {
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		buffer.WriteString(fmt.Sprintf("    %s:%d\r\n", file, line))
	}
	log.Error(buffer.String())
}

func logRequestAndResponse(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	start := time.Now()
	chain.ProcessFilter(req, resp)

	// Always log error response
	log.Infof("%s - \"%s %s %s\" %d %d %dms",
		utils.RemoteIp(req.Request),
		req.Request.Method,
		req.Request.URL,
		req.Request.Proto,
		resp.StatusCode(),
		resp.ContentLength(),
		time.Since(start)/time.Millisecond,
	)
}

func cors(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	resp.AddHeader("Access-Control-Allow-Origin", "*")

	resp.AddHeader("Content-Type", "application/json, application/x-www-form-urlencoded")
	resp.AddHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	resp.AddHeader("Access-Control-Allow-Headers", "Accept, Content-Type, Accept-Encoding, X-Authorization")

	if req.Request.Method == "OPTIONS" {
		resp.WriteHeader(http.StatusOK)
		resp.Write([]byte("ok"))
		return
	}

	chain.ProcessFilter(req, resp)
}

func authenticate(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
	// Ignore uris, because do not need authentication
	needAuth, reqPath := true, req.Request.URL.Path
	for _, p := range constants.RequestURLWhiteList {
		if len(reqPath) >= len(p) && reqPath[:len(p)] == p {
			needAuth = false
			break
		}
	}

	if needAuth {
		log.Debugw("request headers", "requestURL", req.Request.URL, "headers", req.Request.Header)

		tokenStr := req.HeaderParameter(constants.AuthorizationTokenKey)
		if tokenStr == "" {
			response.HandleUnauthorized(resp, response.NewTokenValidationError("token not provided"))
			return
		}

		claims, err := apiRuntime.ParseToken(tokenStr)
		if err != nil {
			response.HandleUnauthorized(resp, response.NewTokenValidationError("parse token", err))
			return
		}

		// check token is exists
		//if cache.RedisClient != nil {
		//	pattern := fmt.Sprintf("kubesphere:user:*:token:%s", tokenStr)
		//	keys, err := cache.RedisClient.Keys(pattern)
		//	if err == nil && len(keys) == 0 {
		//		response.HandleError(resp, response.NewTokenValidationError("token not be found in cache"))
		//		return
		//	} else if err != nil {
		//		log.Errorf("keys %q, err: %v", pattern, err)
		//	}
		//}

		req.SetAttribute(constants.UserContextAttribute, claims.Username)
	}

	chain.ProcessFilter(req, resp)
}
