package rego

import (
	"fmt"
	"strings"
)

// Matchers are all of the matchers that can be applied to constraints.
type Matchers struct {
	KindMatchers       KindMatchers
	MatchLabelsMatcher MatchLabelsMatcher
	NamespaceMatchers NamespaceMatchers
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

type NamespaceMatchers []string

func (n NamespaceMatchers) String() string {
	var result string
	for _, v := range n {
		result += fmt.Sprintf("%s ", v)
	}

	return strings.TrimSpace(result)
}

// Matchers returns all of the matchers found in the rego file.
func (r Rego) Matchers() (Matchers, error) {
	var matchers Matchers
	for _, comment := range r.headerComments {
		if strings.HasPrefix(comment, "@kinds") {
			matchers.KindMatchers = getKindMatchers(comment)
		}
		if strings.HasPrefix(comment, "@matchlabels") {
			var err error
			matchers.MatchLabelsMatcher, err = getMatchLabelsMatcher(comment)
			if err != nil {
				return matchers, err
			}
		}
		if strings.HasPrefix(comment, "@namespaces") {
			matchers.NamespaceMatchers = getNamespacesMatchers(comment)
		}
	}

	return matchers, nil
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

		kindMatchers = append(kindMatchers, kindMatcher) }

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

func getNamespacesMatchers(comment string) NamespaceMatchers {
	var namespaceMatchers NamespaceMatchers
	matcherText := strings.TrimSpace(strings.SplitAfter(comment, "@namespaces")[1])
	namespaceMatcherGroups := strings.Split(matcherText, " ")

	for _, matcher := range namespaceMatcherGroups {
		namespaceMatchers = append(namespaceMatchers, matcher)
	}

	return namespaceMatchers
}
