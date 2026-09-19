#!/system/bin/sh
# KernelSU module service.sh for zygisk_vector
# Detach a watchdog so late-load can exit without SIGHUP on vectord.
MODDIR="${0%/*}"
BB=/data/adb/ksu/bin/busybox
PIDF=/data/adb/lspd/watchdog.pid
mkdir -p /data/adb/lspd
if [ -f "$PIDF" ]; then
  opid=$(cat "$PIDF")
  case $(tr '\0' ' ' < /proc/$opid/cmdline 2>/dev/null) in
    *daemon-watchdog.sh*) exit 0 ;;
  esac
fi
chmod 755 "$MODDIR/daemon-watchdog.sh" "$MODDIR/daemon" 2>/dev/null
if [ -x "$BB" ]; then
  "$BB" setsid "$MODDIR/daemon-watchdog.sh" </dev/null >/dev/null 2>&1 &
else
  setsid "$MODDIR/daemon-watchdog.sh" </dev/null >/dev/null 2>&1 &
fi
exit 0
