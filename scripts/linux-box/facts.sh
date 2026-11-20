#!/bin/sh
# What this Linux kernel and container allow, as plain facts. Run inside the container.
# Nothing here changes the system; it only reads and tries.
say() { printf '%s\n' "$*"; }
say "kernel=$(uname -r)"
say "arch=$(uname -m)"
say "os=$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
say "userns-sysctl-unprivileged_userns_clone=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo absent)"
say "userns-sysctl-apparmor_restrict=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo absent)"
say "userns-max=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo absent)"
say "lsm=$(cat /sys/kernel/security/lsm 2>/dev/null || echo unknown)"
say "uid=$(id -u)"
say "capeff=$(awk '/^CapEff/{print $2}' /proc/self/status)"
say "seccomp-mode=$(awk '/^Seccomp:/{print $2}' /proc/self/status)"
if command -v bwrap >/dev/null 2>&1; then
  say "bwrap=$(bwrap --version 2>&1)"
  if bwrap --unshare-all --ro-bind / / --proc /proc --dev /dev -- /bin/true 2>/tmp/bwrap.err; then say "bwrap-unshare-all=works"; else say "bwrap-unshare-all=fails: $(tr '\n' ' ' </tmp/bwrap.err)"; fi
else
  say "bwrap=not installed"
fi
