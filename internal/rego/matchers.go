package rego

import (
	"fmt"
	"log"
	"strings"
)

// Matchers are all of the matchers that can be applied to constraints.
type Matchers struct {
	KindMatchers       []KindMatcher
	MatchLabelsMatcher MatchLabelsMatcher
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

// MatchLabelsMatcher is the matcher to generate `constraints.spec.match.labelSelector.matchLabels`.
type MatchLabelsMatcher map[string]string

// Matchers returns all of the matchers found in the rego file.
func (r Rego) Matchers() Matchers {
	var matchers Matchers
	for _, comment := range r.comments {
		if strings.HasPrefix(comment, "@kinds") {
			matchers.KindMatchers = getKindMatchers(comment)
		}
		if strings.HasPrefix(comment, "@matchlabels") {
			var err error
			matchers.MatchLabelsMatcher, err = getMatchLabelsMatcher(comment)
			if err != nil {
				log.Fatal(err)
			}
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

func getMatchLabelsMatcher(comment string) (MatchLabelsMatcher, error) {
	matcher := make(map[string]string)

	matcherText := strings.TrimSpace(strings.SplitAfter(comment, "@matchlabels")[1])

	for _, token := range strings.Fields(matcherText) {
		split := strings.Split(token, "=")
		if len(split) != 2 {
			return nil, fmt.Errorf("invalid @matchlabels annotation token: %s", token)
		}
		matcher[split[0]] = split[1]
	}
	return matcher, nil
}
