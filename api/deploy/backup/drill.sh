#!/bin/bash
# Restore drill on throwaway containers: S3-compatible storage (MinIO) or an SFTP server
# (DRILL_TARGET=s3|sftp), a
# PostgreSQL with archiving, a base backup, rows written before and after a
# marked time, a point-in-time restore into a fresh container, row counts
# compared. Touches only containers, volumes and a network named bkp-drill-*
# and removes them (and the image it builds) at the end. It never reads the
# real stack's .env or secrets; every credential is generated here.
#
#   api/deploy/backup/drill.sh
set -Eeuo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
p=bkp-drill
img=$p-pg:test
BASE_IMAGE="${DRILL_POSTGRES_IMAGE:-postgres:17}" # also postgres:17-alpine
S3_IMG="${DRILL_S3_IMAGE:-bitnamilegacy/minio:latest}"
SFTP_IMG="${DRILL_SFTP_IMAGE:-atmoz/sftp:alpine}"
target="${DRILL_TARGET:-s3}" # s3 (MinIO over TLS) or sftp
work="$(mktemp -d)"
net=$p-net
log() { echo "[drill $(date -u +%T)] $*"; }
now() { date +%s.%N; }
cleanup() {
	set +e
	docker rm -f -v $p-s3 $p-pg $p-bk $p-restore $p-verify > /dev/null 2>&1
	docker volume rm -f $p-data $p-sock $p-data2 $p-s3data > /dev/null 2>&1
	docker network rm $net > /dev/null 2>&1
	[ -n "${KEEP_IMAGE:-}" ] || docker rmi $img > /dev/null 2>&1
	find "$work" -delete
}
trap cleanup EXIT

command -v docker > /dev/null || { echo "docker is needed" >&2; exit 1; }
mkdir -p "$work/sec"
chmod 700 "$work/sec"
rnd() { openssl rand -hex "$1"; }
printf '%s' "$(openssl rand -base64 32)" > "$work/sec/cipher_pass"
s3key="k$(rnd 8)"
s3secret="s$(rnd 16)"
printf '%s' "$s3key" > "$work/sec/s3_access_key"
printf '%s' "$s3secret" > "$work/sec/s3_secret_key"
pgpass="$(rnd 12)"
# pgBackRest speaks only TLS to S3: the storage gets a throwaway certificate and
# the repository trusts it through s3_ca.pem (the private-CA path).
mkdir -p "$work/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$p-s3" -addext "subjectAltName=DNS:$p-s3" \
	-keyout "$work/certs/private.key" -out "$work/certs/public.crt" 2> /dev/null
chmod 644 "$work/certs/private.key"
cp "$work/certs/public.crt" "$work/sec/s3_ca.pem"

log "build image"
docker build -q --build-arg POSTGRES_IMAGE="$BASE_IMAGE" -t $img "$here" > /dev/null
pguid="$(docker run --rm --entrypoint id $img -u postgres)"
docker network create $net > /dev/null
docker volume create $p-data > /dev/null
docker volume create $p-sock > /dev/null
docker volume create $p-data2 > /dev/null

if [ "$target" = s3 ]; then
	log "start S3-compatible storage"
	docker volume create $p-s3data > /dev/null
	docker run -d --name $p-s3 --network $net --user 0 -e MINIO_ROOT_USER="$s3key" -e MINIO_ROOT_PASSWORD="$s3secret" \
		-v "$work/certs":/certs:ro -v $p-s3data:/data --entrypoint /opt/bitnami/minio/bin/minio "$S3_IMG" \
		server /data --certs-dir /certs > /dev/null
	for _ in $(seq 60); do
		docker run --rm --network $net --entrypoint bash $img -c 'exec 3<>/dev/tcp/'$p'-s3/9000' 2> /dev/null && break
		sleep 1
	done
	docker exec $p-s3 mkdir -p /data/drill # a bucket is a directory of the data volume
	env_args=(-e BACKUP_TARGET=s3 -e BACKUP_S3_ENDPOINT=$p-s3:9000 -e BACKUP_S3_BUCKET=drill -e BACKUP_S3_URI_STYLE=path)
else
	log "start SFTP server"
	ssh-keygen -q -t ed25519 -N '' -f "$work/sec/sftp_private_key"
	docker run -d --name $p-s3 --network $net -v "$work/sec/sftp_private_key.pub":/home/drill/.ssh/keys/id.pub:ro \
		"$SFTP_IMG" drill::1001:100:upload > /dev/null
	for _ in $(seq 60); do
		docker run --rm --network $net --entrypoint bash $img -c 'exec 3<>/dev/tcp/'$p'-s3/22' 2> /dev/null && break
		sleep 1
	done
	fp="$(docker exec $p-s3 cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}' | base64 -d | sha256sum | cut -d' ' -f1)"
	env_args=(-e BACKUP_TARGET=sftp -e BACKUP_SFTP_HOST=$p-s3 -e BACKUP_SFTP_USER=drill -e BACKUP_SFTP_PATH=/upload/repo
		-e BACKUP_SFTP_HOST_FINGERPRINT="$fp")
fi
env_args+=(-e DB_SUPERUSER=drill -e BACKUP_ARCHIVE_TIMEOUT=30)
mounts=(-v $p-data:/var/lib/postgresql/data -v $p-sock:/var/run/postgresql -v "$work/sec":/run/backup-secrets:ro)
tmpfs=(--tmpfs /etc/pgbackrest:mode=0750 --tmpfs /var/spool/pgbackrest:mode=0750,uid=$pguid,gid=$pguid)

log "start PostgreSQL with archiving, and the backup service"
docker run -d --name $p-pg --network $net --entrypoint pg-entrypoint.sh "${env_args[@]}" -e POSTGRES_USER=drill \
	-e POSTGRES_PASSWORD="$pgpass" -e POSTGRES_DB=drill "${mounts[@]}" "${tmpfs[@]}" $img postgres > /dev/null
docker run -d --name $p-bk --network $net --entrypoint backup-entrypoint.sh "${env_args[@]}" \
	"${mounts[@]}" "${tmpfs[@]}" --tmpfs /var/log/pgbackrest:mode=0750,uid=$pguid,gid=$pguid $img scheduler > /dev/null
psql() { docker exec -i $p-pg psql -qAtX -U drill -d drill "$@"; }
pgb() { docker exec $p-bk gosu postgres pgbackrest --stanza=openctem "$@"; }
t0=$(now)
for _ in $(seq 120); do
	docker exec $p-bk gosu postgres pgbackrest --stanza=openctem info 2> /dev/null | grep -q 'full backup:' && break
	sleep 2
done
log "first full backup present after $(printf '%.0f' "$(echo "$(now) - $t0" | bc)") s"

psql -c "create table drill(n int primary key, at timestamptz default now())"
psql -c "insert into drill(n) select generate_series(1,1000)"
log "rows before the marker: $(psql -c 'select count(*) from drill')"
pgb backup --type=diff > /dev/null
log "differential backup taken"
psql -c "insert into drill(n) select generate_series(1001,1200)"
sleep 3
marker="$(psql -c "select to_char(now() at time zone 'utc','YYYY-MM-DD HH24:MI:SS.US+00')")"
sleep 3
psql -c "insert into drill(n) select generate_series(1201,1500)"
total="$(psql -c 'select count(*) from drill')"
expected="$(psql -c "select count(*) from drill where at <= '$marker'")"
psql -c "select pg_switch_wal()" > /dev/null
log "marker $marker UTC; rows total $total, rows up to the marker $expected"
for _ in $(seq 60); do
	[ "$(psql -c "select last_archived_wal is not null and last_archived_time > now() - interval '1 minute' from pg_stat_archiver")" = t ] && break
	sleep 2
done
log "archiver: $(psql -c 'select archived_count||'"' archived, '"'||failed_count||'"' failed'"' from pg_stat_archiver')"

log "stop the source database; restore to the marker into a fresh volume"
docker stop $p-bk $p-pg > /dev/null
t1=$(now)
docker run --name $p-restore --rm --network $net --entrypoint backup-entrypoint.sh "${env_args[@]}" \
	-v $p-data2:/var/lib/postgresql/data -v "$work/sec":/run/backup-secrets:ro "${tmpfs[@]}" \
	--tmpfs /var/log/pgbackrest:mode=0750,uid=$pguid,gid=$pguid $img restore --type=time "--target=$marker" --target-action=promote > "$work/restore.log" 2>&1
t2=$(now)
log "restore (download + unpack) took $(printf '%.1f' "$(echo "$t2 - $t1" | bc)") s"
# The verification container must not archive into the repository.
docker run -d --name $p-verify --network $net --entrypoint bash "${env_args[@]}" -e POSTGRES_USER=drill \
	-v $p-data2:/var/lib/postgresql/data -v "$work/sec":/run/backup-secrets:ro "${tmpfs[@]}" $img \
	-c '. /usr/local/bin/render-conf.sh; render_conf; exec docker-entrypoint.sh postgres -c archive_mode=off' > /dev/null
for _ in $(seq 90); do
	[ "$(docker exec $p-verify psql -qAtX -U drill -d drill -c 'select not pg_is_in_recovery()' 2> /dev/null)" = t ] && break
	sleep 2
done
t3=$(now)
got="$(docker exec $p-verify psql -qAtX -U drill -d drill -c 'select count(*) from drill')"
log "restored rows: $got (expected $expected); recovery to promoted took $(printf '%.1f' "$(echo "$t3 - $t1" | bc)") s in total"
[ "$got" = "$expected" ] || { echo "DRILL FAILED: $got rows, expected $expected" >&2; docker logs $p-verify 2>&1 | tail -20 >&2; exit 1; }
[ "$got" -lt "$total" ] || { echo "DRILL FAILED: restore did not stop at the marker" >&2; exit 1; }
log "DRILL OK: base backup + WAL replay stopped at the marker ($got of $total rows)"
