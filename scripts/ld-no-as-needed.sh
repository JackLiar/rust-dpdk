# tools/ld-no-as-needed.sh
#!/usr/bin/env bash
args=()
for a in "$@"; do
  if [ "$a" = "-Wl,--as-needed" ]; then a="-Wl,--no-as-needed"; fi
  args+=("$a")
done
exec cc "${args[@]}"