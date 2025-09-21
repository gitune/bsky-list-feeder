#!/bin/bash

# Check if a handle is provided as an argument
if [ -z "$1" ]; then
  echo "Usage: $0 <handle>"
  echo "Example: $0 bsky.app"
  exit 1
fi

HANDLE=$1

# Use the public API to resolve the handle to a DID
curl -s "https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=$HANDLE" | jq -r .did
