package web

import _ "embed"

//go:embed index.html
var indexHTML string

//go:embed intel.html
var intelHTML string

//go:embed vendor/vis-network.min.js
var visNetworkJS []byte
