#!/bin/bash

# X3 Docker Entrypoint
# Reads x3.conf-dist, replaces all %VARIABLE% placeholders with environment
# variable values, and writes out x3.conf
#
# If x3.conf already exists (e.g., bind-mounted), skip generation and use it as-is.
# Volume permissions are handled by init container in docker-compose.

BASECONFDIST=/x3/x3.conf-dist
BASECONF=/x3/x3.conf

# Set X3_VALGRIND=1 in environment to run under Valgrind

# Create core dump directory and change to it (for both paths)
mkdir -p /x3/cores 2>/dev/null || true
cd /x3/cores

# Helper function to run command (optionally under valgrind)
run_cmd() {
    if [ "${X3_VALGRIND:-0}" = "1" ]; then
        echo "Running with Valgrind (X3_VALGRIND=1)"
        exec valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
            --log-file=/x3/cores/valgrind.log "$@"
    else
        exec "$@"
    fi
}

# If config already exists, use it as-is
if [ -f "$BASECONF" ] && [ -s "$BASECONF" ]; then
    echo "Using existing $BASECONF (bind-mounted or pre-configured)"
    run_cmd "$@"
fi

# Set defaults for required variables (can be overridden by environment)
: "${X3_GENERAL_NAME:=x3.network}"
: "${X3_GENERAL_BIND_ADDRESS:=127.0.0.1}"
: "${X3_GENERAL_DESCRIPTION:=Network Services}"
: "${X3_GENERAL_DOMAIN:=example.com}"
: "${X3_GENERAL_NUMERIC:=199}"
: "${X3_UPLINK_ADDRESS:=127.0.0.1}"
: "${X3_UPLINK_PORT:=8888}"
: "${X3_UPLINK_PASSWORD:=changeme}"
: "${X3_UPLINK_SSL:=0}"
: "${X3_UPLINK_SSL_VERIFY:=0}"

# Copy the template to the output location
cp "$BASECONFDIST" "$BASECONF"

# Find all %VARIABLE% placeholders in the config and substitute them
# with corresponding environment variable values
grep -oE '%[A-Za-z_][A-Za-z0-9_]*%' "$BASECONF" | sort -u | while read -r placeholder; do
    # Extract variable name (remove the % signs)
    varname="${placeholder:1:-1}"

    # Get the value from environment (indirect expansion)
    value="${!varname}"

    # Only substitute if the variable is set
    if [ -n "$value" ]; then
        # Escape special characters for sed (/, &, \)
        escaped_value=$(printf '%s\n' "$value" | sed -e 's/[\/&]/\\&/g')
        sed -i "s|${placeholder}|${escaped_value}|g" "$BASECONF"
    else
        echo "Warning: No value set for ${varname}, leaving ${placeholder} unchanged"
    fi
done

echo "Generated $BASECONF from template"

# Run the command passed to docker (CMD from Dockerfile)
run_cmd "$@"
