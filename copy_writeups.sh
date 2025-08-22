#!/usr/bin/env bash

# Usage: ./script.sh /path/to/base_dir
set -euo pipefail

BASE_DIR="${1:-}"
if [[ -z "$BASE_DIR" || ! -d "$BASE_DIR" ]]; then
  echo "Usage: $0 /path/to/base_directory"
  exit 1
fi

# Find .md files (strict .md extension), exclude anything ending in .swp, search for literal match, and copy
find "$BASE_DIR" -type f -name "*.md" ! -name "*.swp" -print0 \
  | xargs -0 grep -l -- "Platform: CyberDefenders" \
  | while IFS= read -r file; do
      cp -- "$file" .
    done

echo "Done: copied matching .md files (excluding swap files) to $(pwd)"

