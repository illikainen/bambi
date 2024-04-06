package metadata

import (
	_ "embed"
	"encoding/json"
)

var metadata struct {
	Name    string
	Version string
}

//go:embed metadata.json
var metadataBytes []byte

func init() {
	err := json.Unmarshal(metadataBytes, &metadata)
	if err != nil {
		panic(err)
	}
}

func Name() string {
	return metadata.Name
}

func Version() string {
	return metadata.Version
}
