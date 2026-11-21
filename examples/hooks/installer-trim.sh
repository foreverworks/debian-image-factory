#!/bin/sh
# Runs inside the installer's chroot with no network: drop documentation the RAM kit never reads.
set -eu
rm -rf /usr/share/doc/* /usr/share/man/* /usr/share/info/*
