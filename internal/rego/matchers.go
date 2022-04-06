package rego

import (
	"fmt"
	"strings"
)

// Matchers are all of the matchers that can be applied to constraints.
type Matchers struct {
	KindMatchers             KindMatchers
	MatchLabelsMatcher       MatchLabelsMatcher
	MatchExpressionsMatcher  []MatchExpressionMatcher
	NamespaceMatcher         []string
	ExcludedNamespaceMatcher []string
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

// MatchExpressionsMatcher is the matcher to generate `constraints.spec.match.labelSelector.matchExpressions`.
type MatchExpressionMatcher struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

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
		if commentStartsWith(comment, "@kinds") {
			m, err := getKindMatchers(comment)
			if err != nil {
				return Matchers{}, fmt.Errorf("get kind matchers: %w", err)
			}
			matchers.KindMatchers = m
		}

		if commentStartsWith(comment, "@matchlabels") {
			m, err := getMatchLabelsMatcher(comment)
			if err != nil {
				return Matchers{}, fmt.Errorf("get match labels matcher: %w", err)
			}
			matchers.MatchLabelsMatcher = m
		}

		if commentStartsWith(comment, "@matchExpression") {
			m, err := getMatchExperssionsMatcher(comment)
			if err != nil {
				return Matchers{}, fmt.Errorf("get match expression matcher: %w", err)
			}
			matchers.MatchExpressionsMatcher = append(matchers.MatchExpressionsMatcher, m)
		}

		if commentStartsWith(comment, "@namespaces") {
			m, err := getStringListMatcher("@namespaces", comment)
			if err != nil {
				return Matchers{}, fmt.Errorf("get match namespaces matcher: %w", err)
			}
			matchers.NamespaceMatcher = append(matchers.NamespaceMatcher, m...)
		}

		if commentStartsWith(comment, "@excludedNamespaces") {
			m, err := getStringListMatcher("@excludedNamespaces", comment)
			if err != nil {
				return Matchers{}, fmt.Errorf("get match excludedNamespaces matcher: %w", err)
			}
			matchers.ExcludedNamespaceMatcher = append(matchers.ExcludedNamespaceMatcher, m...)
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

func getMatchExperssionsMatcher(comment string) (MatchExpressionMatcher, error) {
	argSpit := strings.TrimSpace(strings.SplitAfter(comment, "@matchExpression")[1])
	lineSplit := strings.Split(argSpit, " ")
	if len(lineSplit) != 2 && len(lineSplit) != 3 {
		return MatchExpressionMatcher{}, fmt.Errorf("too few parameters: have %d, need 2 or 3", len(lineSplit))
	}
	matcher := MatchExpressionMatcher{
		Key:      lineSplit[0],
		Operator: lineSplit[1],
	}
	if len(lineSplit) == 3 {
		matcher.Values = strings.Split(lineSplit[2], ",")
	}

	return matcher, nil
}

func getStringListMatcher(tag, comment string) ([]string, error) {
	argSpit := strings.SplitAfter(comment, tag)
	if len(argSpit) == 0 {
		return nil, fmt.Errorf("no match for tag %q in comment %q", tag, comment)
	}
	lineSplit := strings.Split(strings.TrimSpace(argSpit[1]), " ")
	if len(lineSplit) == 1 {
		return nil, fmt.Errorf("no values provided for tag: %s", tag)
	}

	return lineSplit, nil
}

func commentStartsWith(comment string, keyword string) bool {
	return strings.HasPrefix(strings.TrimSpace(comment), keyword)
}
