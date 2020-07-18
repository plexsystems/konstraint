package rego

import (
	"path/filepath"
	"strings"
)

// File is a parsed Rego file
type File struct {
	FilePath       string
	PackageName    string
	ImportPackages []string
	Contents       string
	RulesActions   []string
	Comments       []string
}

// Kind returns a Kubernetes Kind from the File's path
func (f *File) Kind() string {
	kind := filepath.Base(filepath.Dir(f.FilePath))
	kind = strings.ReplaceAll(kind, "-", " ")
	kind = strings.Title(kind)
	kind = strings.ReplaceAll(kind, " ", "")

	return kind
}
