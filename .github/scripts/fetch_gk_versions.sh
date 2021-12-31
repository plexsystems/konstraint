#!/usr/bin/env bash

set -eo pipefail

gk_versions=$(curl -f -L https://open-policy-agent.github.io/gatekeeper/charts/index.yaml 2>/dev/null | yq eval '.entries.gatekeeper[] | select(.version | (contains("beta") or contains("rc")) | not) | .version' -)

latest_versions=()
position=0
for version in ${gk_versions}; do
    if [[ "${#latest_versions[@]}" == "3" ]]; then
        break
    fi
    if [[ "${#latest_versions[@]}" == "0" ]]; then
        latest_versions+=($version)
        continue
    fi
    major=$(echo -n ${version} | cut -d"." -f1)
    minor=$(echo -n ${version} | cut -d"." -f2)
    pos_major=$(echo -n ${latest_versions[position]} | cut -d"." -f1)
    pos_minor=$(echo -n ${latest_versions[position]} | cut -d"." -f2)

    if [ "${major}" == "${pos_major}" ] && [ "${minor}" == "${pos_minor}" ]; then
        continue
    fi
    position=$((position+1))
    latest_versions+=(${version})
done

# output json list
versions_concat=""
for version in ${latest_versions[@]}; do
    versions_concat+="\"${version}\", "
done
versions_concat=$(echo -n ${versions_concat} | rev | sed 's/,//' | rev)
echo "[ ${versions_concat} ]"
