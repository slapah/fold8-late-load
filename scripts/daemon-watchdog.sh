#!/system/bin/sh
# Respawn patched Vector daemon.
VEC=/data/adb/modules/zygisk_vector
BB=/data/adb/ksu/bin/busybox
LOG=/data/adb/lspd/watchdog.log
mkdir -p /data/adb/lspd
echo $$ > /data/adb/lspd/watchdog.pid
while true; do
  if ! pidof vectord >/dev/null 2>&1; then
    rm -f /data/adb/lspd/lock
    echo "$(date) start vectord" >> "$LOG"
    if [ -x "$BB" ]; then
      "$BB" setsid "$VEC/daemon" --late-inject --system-server-max-retry=0 </dev/null >/dev/null 2>&1
    else
      setsid "$VEC/daemon" --late-inject --system-server-max-retry=0 </dev/null >/dev/null 2>&1
    fi
    echo "$(date) vectord exited $?" >> "$LOG"
  fi
  sleep 5
done
