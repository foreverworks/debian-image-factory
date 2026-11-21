# The factory's builder image: Debian 13 and the tools that write bytes, every package at one
# archive snapshot (DESIGN 5.4). Build it with scripts/builder, which passes the lock's snapshot.
FROM debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6

ARG SNAPSHOT
LABEL org.opencontainers.image.description="debian-image-factory builder" \
      io.debian-image-factory.snapshot="${SNAPSHOT}"

# http is fine: apt verifies the signed indices, and the base image has no CA certificates yet.
RUN set -eu; \
    test -n "${SNAPSHOT}" || { echo "build argument SNAPSHOT is required" >&2; exit 1; }; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    printf '%s\n' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian/${SNAPSHOT}/" \
      'Suites: trixie trixie-updates' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp' \
      '' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/" \
      'Suites: trixie-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp' \
      > /etc/apt/sources.list.d/debian.sources; \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot; \
    apt-get update; \
    apt-get -y dist-upgrade; \
    apt-get -y install --no-install-recommends \
      mmdebstrap apt dpkg tar gzip cpio squashfs-tools python3 gnupg util-linux \
      debian-archive-keyring ca-certificates; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt/* /var/log/dpkg.log
