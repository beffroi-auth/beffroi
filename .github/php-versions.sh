#!/usr/bin/env bash

# The versions of PHP the suites of ci.yml and application.yml run on, written for GITHUB_OUTPUT as the "include"
# list of their matrix. 8.4 is the floor every composer.json announces, and one of the two builds the specifications
# of the SAML packages ask a green corpus of, PSS refused there by its name (src/xml-security/spec/dsig.md section
# 13). 8.5 is the PHP of the image and of the executable of the terminal client, and the coverage the mutation job
# reads. 8.6 is the latest release. The next one is allowed to fail, and listed only once the phpqa image of it
# exists, which Spomky-Labs/phpqa builds from its first alpha: before that, a job on it could only fail at the pull
# of its container.

set -euo pipefail

next=8.7
matrix='[
    {"php-version": "8.4", "coverage": false, "experimental": false},
    {"php-version": "8.5", "coverage": true, "experimental": false},
    {"php-version": "8.6", "coverage": false, "experimental": false}
]'

if docker manifest inspect "ghcr.io/spomky-labs/phpqa:${next}" > /dev/null 2>&1; then
    matrix=$(jq --arg version "${next}" '. + [{"php-version": $version, "coverage": false, "experimental": true}]' <<< "${matrix}")
fi

echo "matrix=$(jq -c . <<< "${matrix}")"
