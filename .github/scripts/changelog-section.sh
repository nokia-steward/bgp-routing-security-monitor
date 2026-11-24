#!/usr/bin/env bash
# changelog-section.sh TAG [CHANGELOG]
#
# Prints the body of TAG's section of the changelog: the lines after its
# "## " heading, up to the next "## " heading, without leading or trailing
# blank lines. The heading is "## v0.5.0 ..." or "## 0.5.0 ...". A
# pre-release tag (v0.5.0-rc.1) uses its own section if there is one, else
# the section of the release it precedes (v0.5.0). Exits 1 if neither has
# a section, so a release is never published with empty notes.
set -euo pipefail

tag=${1:?usage: changelog-section.sh TAG [CHANGELOG]}
changelog=${2:-CHANGELOG.md}

section() { # $1: tag, with or without the leading v
	local v=${1#v}
	awk -v a="## v${v}" -v b="## ${v}" '
		function heading(line, h) {
			return substr(line, 1, length(h)) == h &&
				(length(line) == length(h) || substr(line, length(h) + 1, 1) == " ")
		}
		/^## / { if (found) exit; if (heading($0, a) || heading($0, b)) { found = 1; next } }
		found { lines[++n] = $0 }
		END {
			first = 1; while (first <= n && lines[first] ~ /^[[:space:]]*$/) first++
			last = n; while (last >= first && lines[last] ~ /^[[:space:]]*$/) last--
			for (i = first; i <= last; i++) print lines[i]
			exit (found && last >= first) ? 0 : 1
		}' "$changelog"
}

if section "$tag"; then
	exit 0
fi
if [[ $tag == *-* ]] && section "${tag%%-*}"; then
	exit 0
fi
echo "changelog-section.sh: no section for $tag in $changelog" >&2
exit 1
