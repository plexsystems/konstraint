package rego

// File is a parsed Rego file
type File struct {
	FilePath       string
	PackageName    string
	ImportPackages []string
	Contents       string
	RulesActions   []string
}
