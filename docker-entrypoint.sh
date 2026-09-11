#!/bin/sh
set -eu

# A platform-mounted /data directory can arrive owned by root even though the
# application runs as an unprivileged user. Prepare only the app's data files,
# then permanently drop privileges before starting Gunicorn.
chown keylight:keylight /data
chmod 0750 /data

for data_file in \
    /data/findings.db \
    /data/findings.db-journal \
    /data/findings.db-shm \
    /data/findings.db-wal \
    /data/fingerprint.key
do
    if [ -e "$data_file" ]; then
        chown keylight:keylight "$data_file"
    fi
done

exec gosu keylight "$@"
