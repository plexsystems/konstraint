package commands

import (
	"path/filepath"
	"strings"
)

// Matchers are all of the matchers that can be applied to constraints.
type Matchers struct {
	KindMatchers []KindMatcher
}

// KindMatcher are the matchers that are applied to constraints.
type KindMatcher struct {
	APIGroup string
	Kind     string
}

// GetMatchersFromComments returns all of the matchers found in the collection of comments.
func GetMatchersFromComments(comments []string) Matchers {
	var matchers Matchers
	for _, comment := range comments {
		if strings.Contains(strings.ToLower(comment), "@kinds") {
			matchers.KindMatchers = getKindMatchers(comment)
		}
	}

	return matchers
}

// GetKindFromPath returns the kind of the resource based on its file path.
func GetKindFromPath(path string) string {
	name := getNameFromPath(path)
	kind := strings.ReplaceAll(name, " ", "")

	return kind
}

func getKindMatchers(comment string) []KindMatcher {
	var kindMatchers []KindMatcher

	kindMatcherGroups := strings.Split(comment, " ")[2:]
	for _, kindMatcherGroup := range kindMatcherGroups {
		kindMatcherSegments := strings.Split(kindMatcherGroup, "/")

		kindMatcher := KindMatcher{
			APIGroup: kindMatcherSegments[0],
			Kind:     kindMatcherSegments[1],
		}

		kindMatchers = append(kindMatchers, kindMatcher)
	}

	return kindMatchers
}

func getNameFromPath(path string) string {
	name := filepath.Base(filepath.Dir(path))
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.Title(name)

	return name
}
