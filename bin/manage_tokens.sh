#!/bin/bash
#
# Utility to manage .tokens.json for Passive DNS server authentication
#
# Usage: ./manage_tokens.sh [add|list|remove|init] [args]

TOKEN_FILE=".tokens.json"

# Ensure jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required. Install it with 'sudo apt install jq' or equivalent."
    exit 1
fi

# Generate a random 32-char token
generate_token() {
    openssl rand -hex 16
}

# Initialize .tokens.json if missing
init_file() {
    if [ ! -f "$TOKEN_FILE" ]; then
        echo '{"tokens": []}' > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"
        echo "Initialized $TOKEN_FILE"
    else
        echo "$TOKEN_FILE already exists"
    fi
}

# Add a token
add_token() {
    local desc="$1"
    local expires="$2"
    local token=$(generate_token)
    
    if [ ! -f "$TOKEN_FILE" ]; then
        init_file
    fi
    
    local entry="{\"value\": \"$token\""
    [ -n "$desc" ] && entry="$entry, \"description\": \"$desc\""
    [ -n "$expires" ] && entry="$entry, \"expires\": \"$expires\""
    entry="$entry}"
    
    jq ".tokens += [$entry]" "$TOKEN_FILE" > tmp.json && mv tmp.json "$TOKEN_FILE"
    echo "Added token: $token"
}

# List tokens
list_tokens() {
    if [ ! -f "$TOKEN_FILE" ]; then
        echo "No $TOKEN_FILE found"
        exit 1
    fi
    jq -r '.tokens[] | "Token: \(.value) | Desc: \(.description // "N/A") | Expires: \(.expires // "N/A")"' "$TOKEN_FILE"
}

# Remove a token
remove_token() {
    local token="$1"
    if [ ! -f "$TOKEN_FILE" ]; then
        echo "No $TOKEN_FILE found"
        exit 1
    fi
    jq "del(.tokens[] | select(.value == \"$token\"))" "$TOKEN_FILE" > tmp.json && mv tmp.json "$TOKEN_FILE"
    echo "Removed token: $token"
}

# Main logic
case "$1" in
    "init")
        init_file
        ;;
    "add")
        add_token "$2" "$3"  # Args: description, expires (e.g., "2025-12-31T00:00:00Z")
        ;;
    "list")
        list_tokens
        ;;
    "remove")
        if [ -z "$2" ]; then
            echo "Usage: $0 remove <token>"
            exit 1
        fi
        remove_token "$2"
        ;;
    *)
        echo "Usage: $0 [init|add|list|remove] [args]"
        echo "  init: Initialize .tokens.json"
        echo "  add [desc] [expires]: Add a token with optional description and expiration"
        echo "  list: List all tokens"
        echo "  remove <token>: Remove a specific token"
        exit 1
        ;;
esac
