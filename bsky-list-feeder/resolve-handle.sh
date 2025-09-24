#!/bin/bash

# Check if both a file path and a handle are provided as arguments
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <output_file> <handle>"
  echo "Example: $0 user_did.txt bsky.app"
  exit 1
fi

OUTPUT_FILE=$1
HANDLE=$2

# If the handle doesn't contain a period, append .bsky.social
if [[ ! "$HANDLE" =~ \. ]]; then
  HANDLE="$HANDLE.bsky.social"
fi

# Use the public API to resolve the handle to a DID
DID=$(curl -s "https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=$HANDLE" | jq -r .did)

# Check if a DID was successfully resolved
if [ -n "$DID" ] && [ "$DID" != "null" ]; then
  # Create a backup of the output file
  cp -p "$OUTPUT_FILE" "$OUTPUT_FILE.old" 2>/dev/null

  # Append the resolved DID to the output file
  echo "$DID" >> "$OUTPUT_FILE"
  echo "Resolved DID for $HANDLE has been appended to $OUTPUT_FILE."
else
  echo "Failed to resolve DID for handle: $HANDLE"
fi
