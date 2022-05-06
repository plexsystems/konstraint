package rego

import (
	"fmt"
	"sort"
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

// kindMatchersMap is internal representation of KindMatchers
// it maps apiGroup to a slice of kinds
type kindMatchersMap map[string][]string

// KindMatcher is the matcher to generate `constraints.spec.match.kinds`
type KindMatcher struct {
	APIGroup string
	Kinds    []string
}

// KindMatchers is a slice of KindMatcher
type KindMatchers []KindMatcher

func (k KindMatchers) String() string {
	var result string
	for _, kindMatcher := range k {
		apiGroup := kindMatcher.APIGroup
		if apiGroup == "" {
			apiGroup = "core"
		}
		for _, kind := range kindMatcher.Kinds {
			result += apiGroup + "/" + kind + " "
		}
	}

	result = strings.TrimSpace(result)
	return result
}

// addIfNotPresent adds an apiGroup/kind matcher to the map
// unless it's already present
//
// it also transforms apiGroup `"core"` to `""`
func (k kindMatchersMap) addIfNotPreset(apiGroup, kind string) {
	if apiGroup == "core" {
		apiGroup = ""
	}
	for _, item := range k[apiGroup] {
		if strings.EqualFold(kind, item) {
			return
		}
	}
	k[apiGroup] = append(k[apiGroup], kind)
}

// convert converts kindMatchersMap to KindMatchers,
// sorted by apiGroup, with kinds in each apiGroupKinds sorted
func (k kindMatchersMap) convert() KindMatchers {
	apiGroups := make([]string, 0, len(k))
	for apiGroup := range k {
		apiGroups = append(apiGroups, apiGroup)
	}
	sort.Strings(apiGroups)

	result := make(KindMatchers, len(apiGroups))
	for i, apiGroup := range apiGroups {
		result[i].APIGroup = apiGroup
		kinds := k[apiGroup]
		sort.Strings(kinds)
		result[i].Kinds = kinds
	}

	return result
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
	matchers := Matchers{
		MatchLabelsMatcher: make(MatchLabelsMatcher),
	}

	kindMatchers := make(kindMatchersMap)

	for _, comment := range r.headerComments {
		if commentStartsWith(comment, "@kinds") {
			err := appendKindMatchers(kindMatchers, comment)
			if err != nil {
				return Matchers{}, fmt.Errorf("get kind matchers: %w", err)
			}
		}

		if commentStartsWith(comment, "@matchlabels") {
			m, err := getMatchLabelsMatcher(comment)
			if err != nil {
				return Matchers{}, fmt.Errorf("get match labels matcher: %w", err)
			}
			for k, v := range m {
				matchers.MatchLabelsMatcher[k] = v
			}
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

	if len(kindMatchers) > 0 {
		matchers.KindMatchers = kindMatchers.convert()
	}

	return matchers, nil
}

func appendKindMatchers(kindMatchersMap kindMatchersMap, comment string) error {
	kindMatcherText := strings.TrimSpace(strings.SplitAfter(comment, "@kinds")[1])
	kindMatcherGroups := strings.Split(kindMatcherText, " ")

	for _, kindMatcherGroup := range kindMatcherGroups {
		kindMatcherSegments := strings.Split(kindMatcherGroup, "/")
		if len(kindMatcherSegments) != 2 {
			return fmt.Errorf("invalid @kinds: %s", kindMatcherGroup)
		}
		kindMatchersMap.addIfNotPreset(kindMatcherSegments[0], kindMatcherSegments[1])
	}

	return nil
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
