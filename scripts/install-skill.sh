#!/bin/sh
set -eu
# Install a symlink to the canonical skill; do not overwrite existing entries.
client=${1:-}
project=${2:-.}
case "$client" in
 codex) sub=.agents/skills ;;
 claude) sub=.claude/skills ;;
 *) echo 'usage: install-skill.sh codex|claude [project-directory]' >&2; exit 2 ;;
esac
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../skills/vulnograph" && pwd)
project_dir=$(CDPATH= cd -- "$project" && pwd)
target=$project_dir/$sub/vulnograph
if [ -e "$target" ] || [ -L "$target" ]; then
 echo 'Target already exists; inspect it before replacing.' >&2
 exit 1
fi
mkdir -p "$project_dir/$sub"
ln -s "$source_dir" "$target"
printf 'Installed vulnograph for %s\n' "$client"
