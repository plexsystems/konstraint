package rego

// RegoFile is a parsed Rego file
type RegoFile struct {
	FilePath       string
	PackageName    string
	ImportPackages []string
	Contents       string
	RulesActions   []string
}
