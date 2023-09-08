// from https://github.com/solo-io/bumblebee/blob/c2422b5bab66754b286d062317e244f02a431dac/builder/builder.go

package builder

import _ "embed"

//go:embed build.sh
var buildScript []byte

func GetBuildScript() []byte {
	return buildScript
}
