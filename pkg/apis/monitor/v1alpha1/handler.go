package v1alpha1

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"bytetrade.io/web3os/bfl/pkg/api/response"
	"bytetrade.io/web3os/bfl/pkg/constants"

	"github.com/emicklei/go-restful/v3"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"kubesphere.io/kubesphere/pkg/simple/client/monitoring"
)

type Handler struct {
}

func newHandler() *Handler {
	return &Handler{}
}

func (h *Handler) GetClusterMetric(req *restful.Request, resp *restful.Response) {
	config := rest.Config{
		Host:        constants.KubeSphereAPIHost,
		BearerToken: req.HeaderParameter(constants.AuthorizationTokenKey),
		APIPath:     "/kapis",
		ContentConfig: rest.ContentConfig{
			GroupVersion: &schema.GroupVersion{
				Group:   "monitoring.kubesphere.io",
				Version: "v1alpha3",
			},
			NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
		},
	}

	client, err := rest.RESTClientFor(&config)
	if err != nil {
		response.HandleError(resp, err)
		return
	}

	metricParam := "cluster_cpu_usage|cluster_cpu_total|cluster_memory_usage_wo_cache|cluster_memory_total|cluster_disk_size_usage|cluster_disk_size_capacity|cluster_net_bytes_transmitted|cluster_net_bytes_received$"

	ctx, cancel := context.WithTimeout(req.Request.Context(), 2*time.Second)
	defer cancel()

	res := client.Get().Resource("cluster").
		Param("metrics_filter", metricParam).Do(ctx)

	if res.Error() != nil {
		response.HandleError(resp, res.Error())
		return
	}

	var metrics Metrics
	data, err := res.Raw()
	if err != nil {
		response.HandleError(resp, res.Error())
		return
	}

	err = json.Unmarshal(data, &metrics)
	if err != nil {
		response.HandleError(resp, res.Error())
		return
	}

	var clusterMetrics ClusterMetrics
	for _, m := range metrics.Results {
		switch m.MetricName {
		case "cluster_cpu_usage":
			clusterMetrics.CPU.Usage = getValue(&m)
		case "cluster_cpu_total":
			clusterMetrics.CPU.Total = getValue(&m)

		case "cluster_disk_size_usage":
			clusterMetrics.Disk.Usage = getValue(&m)
		case "cluster_disk_size_capacity":
			clusterMetrics.Disk.Total = getValue(&m)

		case "cluster_memory_total":
			clusterMetrics.Memory.Total = getValue(&m)
		case "cluster_memory_usage_wo_cache":
			clusterMetrics.Memory.Usage = getValue(&m)

		case "cluster_net_bytes_transmitted":
			clusterMetrics.Net.Transmitted = getValue(&m)

		case "cluster_net_bytes_received":
			clusterMetrics.Net.Received = getValue(&m)
		}
	}

	roundToGB := func(v float64) float64 { return math.Round((v/1000000000.00)*100.00) / 100.00 }
	fmtMetricsValue(&clusterMetrics.CPU, "Cores", func(v float64) float64 { return v })
	fmtMetricsValue(&clusterMetrics.Memory, "GB", roundToGB)
	fmtMetricsValue(&clusterMetrics.Disk, "GB", roundToGB)

	response.Success(resp, clusterMetrics)
}

func getValue(m *monitoring.Metric) float64 {
	if len(m.MetricData.MetricValues) == 0 {
		return 0.0
	}
	return m.MetricData.MetricValues[0].Sample[1]
}

func fmtMetricsValue(v *MetricValue, unit string, unitFunc func(float64) float64) {
	v.Unit = unit

	v.Usage = unitFunc(v.Usage)
	v.Total = unitFunc(v.Total)
	v.Ratio = math.Round((v.Usage / v.Total) * 100)
}
