# The boot checks' image: QEMU, OVMF and the tools that lay a root filesystem onto a scratch disk, from
# the builder's own base and archive snapshot (DESIGN 12). Build it with `scripts/builder vm`, which passes
# the lock's snapshot. Nothing here writes an artifact's bytes: it only boots them.
FROM debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6

ARG SNAPSHOT
LABEL org.opencontainers.image.description="debian-image-factory boot checks" \
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
      qemu-system-x86 ovmf e2fsprogs dosfstools mtools fdisk python3 ca-certificates; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt/* /var/log/dpkg.log
