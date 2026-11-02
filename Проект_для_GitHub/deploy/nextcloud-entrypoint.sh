#!/bin/sh
set -eu
# DAV uploads use Guzzle with verify=true and therefore the system CA bundle.
# Import only the public laboratory CA, never its private signing key.
cp /tmp/pattern-ca.pem /usr/local/share/ca-certificates/course-pattern.crt
update-ca-certificates
exec /entrypoint.sh "$@"
