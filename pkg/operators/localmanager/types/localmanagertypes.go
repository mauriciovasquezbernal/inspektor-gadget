package localmanagertypes

import (
	"fmt"
	"strings"

	"github.com/containerd/containerd/pkg/cri/constants"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	OperatorName           = "LocalManager"
	Runtimes               = "runtimes"
	ContainerName          = "containername"
	Host                   = "host"
	DockerSocketPath       = "docker-socketpath"
	ContainerdSocketPath   = "containerd-socketpath"
	CrioSocketPath         = "crio-socketpath"
	PodmanSocketPath       = "podman-socketpath"
	ContainerdNamespace    = "containerd-namespace"
	RuntimeProtocol        = "runtime-protocol"
	EnrichWithK8sApiserver = "enrich-with-k8s-apiserver"
)

/***** GLOBAL ****/
func GlobalParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          Runtimes,
			Alias:        "r",
			DefaultValue: strings.Join(containerutils.AvailableRuntimes, ","),
			Description: fmt.Sprintf("Comma-separated list of container runtimes. Supported values are: %s",
				strings.Join(containerutils.AvailableRuntimes, ", ")),
			// PossibleValues: containerutils.AvailableRuntimes, // TODO
		},
		{
			Key:          DockerSocketPath,
			DefaultValue: runtimeclient.DockerDefaultSocketPath,
			Description:  "Docker Engine API Unix socket path",
		},
		{
			Key:          ContainerdSocketPath,
			DefaultValue: runtimeclient.ContainerdDefaultSocketPath,
			Description:  "Containerd CRI Unix socket path",
		},
		{
			Key:          CrioSocketPath,
			DefaultValue: runtimeclient.CrioDefaultSocketPath,
			Description:  "CRI-O CRI Unix socket path",
		},
		{
			Key:          PodmanSocketPath,
			DefaultValue: runtimeclient.PodmanDefaultSocketPath,
			Description:  "Podman Unix socket path",
		},
		{
			Key:          ContainerdNamespace,
			DefaultValue: constants.K8sContainerdNamespace,
			Description:  "Containerd namespace to use",
		},
		{
			Key:          RuntimeProtocol,
			DefaultValue: "internal",
			Description:  "Container runtime protocol. Supported values are: internal, cri",
		},
		{
			Key:          EnrichWithK8sApiserver,
			DefaultValue: "false",
			Description:  "Connect to the K8s API server to get further K8s enrichment",
			TypeHint:     params.TypeBool,
		},
	}
}

type GlobalParams struct {
	// Create alias for this type here?
	Runtimes               []*containerutilsTypes.RuntimeConfig
	EnrichWithK8sApiserver bool
	//...
}

func (g *GlobalParams) ToMap() map[string]string {
	return map[string]string{
		//"runtimes":               g.,

	}
	//...
}

func GlobalParamsFromParams(operatorParams *params.Params) any {
	// TODO: a bit of mess
	return &GlobalParams{}
}

/****** INSTANCE *****/

func InstanceParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ContainerName,
			Alias:       "c",
			Description: "Show only data from containers with that name",
			ValueHint:   gadgets.LocalContainer,
		},
		{
			Key:          Host,
			Description:  "Show data from both the host and containers",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
	}
}

type InstanceParams struct {
	ContainerName string
	Host          bool
}

func (l *InstanceParams) ToMap() map[string]string {
	return map[string]string{
		// TODO: use contants above
		"operator.LocalManager.containername": l.ContainerName,
		"operator.LocalManager.host":          fmt.Sprintf("%t", l.Host),
	}
}

func InstanceParamsFromParams(paramValues api.ParamValues) (any, error) {
	params := InstanceParamDescs().ToParams()
	err := params.CopyFromMap(paramValues, "")
	if err != nil {
		return nil, err
	}

	return &InstanceParams{
		ContainerName: params.Get(ContainerName).AsString(),
		Host:          params.Get(Host).AsBool(),
	}, nil
}
