package adminassets

import (
	"embed"
	"io/fs"
)

//go:embed generated
var embeddedFiles embed.FS

func Open() (fs.FS, []byte, bool) {
	generatedFS, err := fs.Sub(embeddedFiles, "generated")
	if err != nil {
		return nil, nil, false
	}

	indexHTML, err := fs.ReadFile(generatedFS, "index.html")
	if err != nil {
		return nil, nil, false
	}

	return generatedFS, indexHTML, true
}
