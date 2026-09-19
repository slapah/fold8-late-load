# Fold 8 late-load KernelSU

Packages I use on a Samsung Galaxy Z Fold 8 (`h8q` / `SM-F971U`) with late-load KernelSU. Late-load means KernelSU gets injected after boot instead of being baked into the boot image.

Device kernel: `6.12.58-android16-6-…-4k` (Android 16/17 One UI).

## What each file is

| File | Role |
|------|------|
| [`packages/LSPromise.apk`](packages/LSPromise.apk) | One-shot exploit app. After a reboot, run it to load KernelSU into the already-running kernel. Root lasts until you reboot again. It is not an Xposed framework. |
| [`packages/KernelSU_v3.2.5_32525.apk`](packages/KernelSU_v3.2.5_32525.apk) | Official KernelSU manager that pairs with this late-load LKM (`versionCode` 32525, signing hash `c371061b…`). Newer managers like 3.3.0 / 32601 will not pair with this kernel. |
| [`packages/Vector-manager-patched.apk`](packages/Vector-manager-patched.apk) | Vector (JingMatrix) manager, patched so it can bind the daemon without waiting on a Zygisk hook inside `system_server`. |
| [`packages/Vector-daemon-patched.apk`](packages/Vector-daemon-patched.apk) | Vector daemon classpath APK. Stock Vector reacts to a failed `system_server` bridge by restarting `system_server`; this build does not, and it publishes `vector.manager` on ServiceManager. Drop it in as `/data/adb/modules/zygisk_vector/daemon.apk`. |

If you are new to this: LSPromise is the thing you tap after a reboot to get root. The Vector daemon is what runs afterward so the Vector manager app has something to talk to. When the daemon is down, Vector shows "Not activated".

## Why Vector needs patching

Stock Vector talks to `system_server` through a Zygisk binder hook. On a late-load setup that hook is never there, because `system_server` was forked at boot, long before KernelSU loaded. So the daemon kills `system_server` to force a retry (`--system-server-max-retry`), and meanwhile the manager waits about 2.5 seconds for a binder that never shows up and draws "Not activated".

This tree works around that. The daemon registers `vector.manager` (`IManagerService`) with ServiceManager and no longer restarts `system_server` when the Zygisk bridge fails (`--system-server-max-retry=0`). The manager looks the service up with `ServiceManager.getService("vector.manager")` on launch. The module's `service.sh` also starts a `setsid` watchdog so the KernelSU late-load can exit without sending SIGHUP to `vectord`.

Base is upstream Vector [JingMatrix/Vector](https://github.com/JingMatrix/Vector) `efb82883` (v2.2 / 3111) and the official KernelSU manager [tiann/KernelSU](https://github.com/tiann/KernelSU) v3.2.5.

## Sources

Vendored under [`src/`](src/):

| Tree | Upstream | Notes |
|------|----------|--------|
| [`src/lspromise`](src/lspromise) | [slapah/lspromise](https://github.com/slapah/lspromise) `9cf09d7` | LSPromise app (userspace + kernel stages). |
| [`src/kernelsu`](src/kernelsu) | [slapah/KernelSU](https://github.com/slapah/KernelSU) branch `kdp-trace` `138b1cf` | LKM + ksud used on this Fold 8. |
| [`src/vector`](src/vector) | [JingMatrix/Vector](https://github.com/JingMatrix/Vector) `efb82883` | Includes the late-load manager/daemon patches described above. |

On-device watchdog scripts: [`scripts/service.sh`](scripts/service.sh), [`scripts/daemon-watchdog.sh`](scripts/daemon-watchdog.sh).

## SHA-256

See [`packages/SHA256SUMS`](packages/SHA256SUMS).

```
1417081413bf7ab1de8e440ecbcb62685037c8f28f048f0f8b79e305b31ab916  KernelSU_v3.2.5_32525.apk
07d548cd6237ce6e668756e2e126db3d91e04a0e138e35c8a5d9ad76e419e91a  LSPromise.apk
f14de097e3e4dde5d419bd0acdacbd4d18cd22e250ca35520cf18508f1b0551c  Vector-daemon-patched.apk
99e3d5fdf3335d6de5ecd2684028207747faac5a1f1c0d634997d7012665987a  Vector-manager-patched.apk
```

## License

- KernelSU: GPL-3.0 (upstream).
- Vector: GPL-3.0 (upstream). These APKs are modified builds of that work.
- LSPromise: as distributed by its author.

Use these only on hardware you own.
