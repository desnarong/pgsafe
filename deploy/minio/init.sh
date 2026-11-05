#!/bin/sh
# Create the dev bucket on the S3 endpoint, then idle so the compose healthcheck
# (test -f /tmp/ready) reports this service healthy.
set -eu
s3() { aws --endpoint-url "$S3_ENDPOINT" s3api "$@"; }

i=0
until s3 list-buckets >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then echo "S3 endpoint $S3_ENDPOINT not reachable" >&2; exit 1; fi
  sleep 1
done

s3 head-bucket --bucket "$BUCKET" >/dev/null 2>&1 || s3 create-bucket --bucket "$BUCKET" >/dev/null
touch /tmp/ready
echo "bucket $BUCKET ready"
exec sleep infinity
