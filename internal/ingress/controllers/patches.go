package controllers

import (
	"context"
	"fmt"

	"bytetrade.io/web3os/bfl/internal/ingress/controllers/config"
	"bytetrade.io/web3os/bfl/pkg/constants"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var patches = map[string][]func(ctx context.Context, r *NginxController, s *config.Server) (*config.Server, error){
	"files": {
		filesNodeApiPatch,
	},
}

var locationAdditionalsCommon = func(node string) []string {
	return []string{
		"auth_request /authelia-verify;",
		"auth_request_set $remote_token $upstream_http_remote_accesstoken;",
		"proxy_set_header Remote-Accesstoken $remote_token;",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"proxy_set_header X-Forwarded-Host $host;",
		"client_body_timeout 60s;",
		"keepalive_timeout 75s;",
		"proxy_read_timeout 60s;",
		"proxy_send_timeout 60s;",
		"proxy_set_header X-BFL-USER " + constants.Username + ";",
		"proxy_set_header X-Authorization $http_x_authorization;",
		"proxy_set_header X-Terminus-Node " + node + ";",
	}
}

var locationAdditionalsForFilesOp = func(node string) []string {
	return []string{
		"auth_request /authelia-verify;",
		"auth_request_set $remote_token $upstream_http_remote_accesstoken;",
		"proxy_set_header Remote-Accesstoken $remote_token;",
		"proxy_set_header X-Real-IP $remote_addr;",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"proxy_set_header X-Forwarded-Host $host;",
		"client_body_timeout 60s;",
		"client_max_body_size 2000M;",
		"proxy_request_buffering off;",
		"keepalive_timeout 75s;",
		"proxy_read_timeout 60s;",
		"proxy_send_timeout 60s;",
		"proxy_set_header X-BFL-USER " + constants.Username + ";",
		"proxy_set_header X-Authorization $http_x_authorization;",
		"proxy_set_header X-Terminus-Node " + node + ";",
		"add_header Access-Control-Allow-Headers \"access-control-allow-headers,access-control-allow-methods,access-control-allow-origin,content-type,x-auth,x-unauth-error,x-authorization\";",
		"add_header Access-Control-Allow-Methods \"PUT, GET, DELETE, POST, OPTIONS\";",
	}
}

func filesNodeApiPatch(ctx context.Context, r *NginxController, s *config.Server) (*config.Server, error) {
	var pods corev1.PodList
	err := r.List(ctx, &pods, client.MatchingLabels{"app": "files"})
	if err != nil {
		klog.Errorf("failed to list pods, %v", err)
		return nil, err
	}

	var nodes corev1.NodeList
	err = r.List(ctx, &nodes)
	if err != nil {
		klog.Errorf("failed to list nodes, %v", err)
		return nil, err
	}

	masterNode := ""
	podMap := map[string]*corev1.Pod{}
	for _, node := range nodes.Items {
		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
			masterNode = node.Name
		}

		for _, pod := range pods.Items {
			if pod.Spec.NodeName == node.Name && pod.Labels["app"] == "files" {
				podMap[node.Name] = &pod
			}
		}
	}

	authRequest := config.Location{
		Prefix:      "= /authelia-verify",
		ProxyPass:   AUTHELIA_URL,
		DirectProxy: true,
		Additionals: []string{
			"internal;",
			"proxy_pass_request_body off;",
			"proxy_set_header Content-Length \"\";",
			"proxy_set_header X-Original-URL $scheme://$http_host$request_uri;",
			"proxy_set_header X-Original-Method $request_method;",
			"proxy_set_header X-Forwarded-For $remote_addr;",
			"proxy_set_header X-Forwarded-Proto $scheme;",
			"proxy_set_header X-BFL-USER " + constants.Username + ";",
			"proxy_set_header X-Authorization $http_x_authorization;",
			"proxy_set_header Cookie $http_cookie;",
		},
	}

	var apis []config.Location
	var podUrl = func(pod *corev1.Pod) string {
		return fmt.Sprintf("http://%s:80", pod.Status.PodIP)
	}

	var nodeLocationPrefix = []string{
		"/api/resources/cache/",
		"/api/preview/cache/",
		"/api/raw/cache/",
		"/api/tree/cache/",
		"/api/resources/external/",
		"/api/preview/external/",
		"/api/raw/external/",
		"/api/tree/external/",
		"/api/mount/",
		"/api/unmount/",
		"/api/smb_history/",
		"/upload/upload-link/",
		"/upload/file-uploaded-bytes/",
		"/api/paste/",
		"/videos/",
		"/api/md5/cache/",
		"/api/md5/external/",
		"/api/permission/cache/",
		"/api/permission/external/",
		"/api/task/",
	}

	var masterLocation = []string{
		"/api/resources/cache/",
		"/api/preview/cache/",
		"/api/resources/external/",
		"/api/preview/external/",
		"/api/paste/",
		"/api/task/",
	}

	for node, pod := range podMap {
		for _, prefix := range nodeLocationPrefix {
			nodeApi := config.Location{
				Prefix:      fmt.Sprintf("%s%s/", prefix, node),
				Additionals: locationAdditionalsForFilesOp(node),

				ProxyPass:   podUrl(pod),
				DirectProxy: true,
			}

			apis = append(apis, nodeApi)
		}

	} // end for each node

	s.Locations = append(s.Locations, authRequest)

	if masterPod, ok := podMap[masterNode]; ok {
		var masterApis []config.Location
		for _, l := range masterLocation {
			masterApi := config.Location{
				Prefix:      l,
				Additionals: locationAdditionalsForFilesOp(masterNode),

				ProxyPass:   podUrl(masterPod),
				DirectProxy: true,
			}

			masterApis = append(masterApis, masterApi)
		}

		s.Locations = append(s.Locations, masterApis...)
	}

	s.Locations = append(s.Locations, apis...)

	return s, nil
}
