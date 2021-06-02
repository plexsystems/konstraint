package rego

import (
	"fmt"
	"strings"
)

// Matchers are all of the matchers that can be applied to constraints.
type Matchers struct {
	KindMatchers       KindMatchers
	MatchLabelsMatcher MatchLabelsMatcher
}

// KindMatchers is the slice of KindMatcher
type KindMatchers []KindMatcher

func (k KindMatchers) String() string {
	var result string
	for _, kindMatcher := range k {
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

func (m MatchLabelsMatcher) String() string {
	var result string
	for k, v := range m {
		result += fmt.Sprintf("%s=%s ", k, v)
	}

	return strings.TrimSpace(result)
}

// Matchers returns all of the matchers found in the rego file.
func (r Rego) Matchers() (Matchers, error) {
	var matchers Matchers
	for _, comment := range r.headerComments {
		if strings.HasPrefix(comment, "@kinds") {
			var err error
			matchers.KindMatchers, err = getKindMatchers(comment)
			if err != nil {
				return Matchers{}, fmt.Errorf("get kind matchers: %w", err)
			}
		}

		if strings.HasPrefix(comment, "@matchlabels") {
			var err error
			matchers.MatchLabelsMatcher, err = getMatchLabelsMatcher(comment)
			if err != nil {
				return Matchers{}, fmt.Errorf("get match labels matcher: %w", err)
			}
		}
	}

	return matchers, nil
}

func getKindMatchers(comment string) ([]KindMatcher, error) {
	kindMatcherText := strings.TrimSpace(strings.SplitAfter(comment, "@kinds")[1])
	kindMatcherGroups := strings.Split(kindMatcherText, " ")

	var kindMatchers []KindMatcher
	for _, kindMatcherGroup := range kindMatcherGroups {
		kindMatcherSegments := strings.Split(kindMatcherGroup, "/")
		if len(kindMatcherSegments) != 2 {
			return nil, fmt.Errorf("invalid @kinds: %s", kindMatcherGroup)
		}

		kindMatcher := KindMatcher{
			APIGroup: kindMatcherSegments[0],
			Kind:     kindMatcherSegments[1],
		}

		kindMatchers = append(kindMatchers, kindMatcher)
	}

	return kindMatchers, nil
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
