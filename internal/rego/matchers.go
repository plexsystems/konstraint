package rego

import (
	"strings"
)

// Matchers are all of the matchers that can be applied to constraints.
type Matchers struct {
	KindMatchers []KindMatcher
}

func (m Matchers) String() string {
	var result string
	for _, kindMatcher := range m.KindMatchers {
		result += kindMatcher.APIGroup + "/" + kindMatcher.Kind + " "
	}
	result = strings.TrimSpace(result)

	return result
}

// KindMatcher are the matchers that are applied to constraints.
type KindMatcher struct {
	APIGroup string
	Kind     string
}

// Matchers returns all of the matchers found in the rego file.
func (r Rego) Matchers() Matchers {
	var matchers Matchers
	for _, comment := range r.comments {
		if strings.HasPrefix(comment, "@kinds") {
			matchers.KindMatchers = getKindMatchers(comment)
		}
	}

	return matchers
}

func getKindMatchers(comment string) []KindMatcher {
	var kindMatchers []KindMatcher

	kindMatcherText := strings.TrimSpace(strings.SplitAfter(comment, "@kinds")[1])
	kindMatcherGroups := strings.Split(kindMatcherText, " ")

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
