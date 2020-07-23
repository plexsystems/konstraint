package commands

import (
	"path/filepath"
	"strings"
)

func GetMatchersFromComments(comments []string) (Matchers, error) {
	var apiGroups []string
	var kinds []string
	for _, comment := range comments {
		if !strings.Contains(strings.ToLower(comment), "@kinds") {
			continue
		}

		kindGroups := strings.Split(comment, " ")[2:]
		for _, kindGroup := range kindGroups {
			kindTokens := strings.Split(kindGroup, "/")
			if !contains(apiGroups, kindTokens[0]) {
				apiGroups = append(apiGroups, kindTokens[0])
			}

			kinds = append(kinds, kindTokens[1])
		}
	}

	resources := Matchers{
		APIGroups: apiGroups,
		Kinds:     kinds,
	}

	return resources, nil
}

func GetNameFromPath(path string) string {
	name := filepath.Base(filepath.Dir(path))
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.Title(name)

	return name
}

func GetKindFromPath(path string) string {
	name := GetNameFromPath(path)
	kind := strings.ReplaceAll(name, " ", "")

	return kind
}
