package frpc

import "bytetrade.io/web3os/bfl/pkg/constants"

const QueueSize = 50

type FrpcConfig struct {
	FrpServer     string
	LocalDomainIp string
	TerminusName  constants.TerminusName
	JWSToken      string
}
