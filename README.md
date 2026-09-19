# Fold 8 late-load KernelSU

Packages used on a **Samsung Galaxy Z Fold 8** (`h8q` / `SM-F971U`) with **late-load KernelSU** (KernelSU is injected after boot; it is not baked into the boot image).

Device kernel: `6.12.58-android16-6-…-4k` (Android 16/17 One UI).

## What each file is

| File | Role |
|------|------|
| [`packages/LSPromise.apk`](packages/LSPromise.apk) | One-shot exploit app. After a reboot, run it to load KernelSU into the *already running* kernel. Root lasts until the next reboot. This is not an Xposed framework. |
| [`packages/KernelSU_v3.2.5_32525.apk`](packages/KernelSU_v3.2.5_32525.apk) | Official KernelSU **manager** that matches this late-load LKM (`versionCode` **32525**, signing hash **HASH1** `c371061b…`). Newer managers (e.g. 3.3.0 / 32601) do not pair with this kernel. |
| [`packages/Vector-manager-patched.apk`](packages/Vector-manager-patched.apk) | Vector (JingMatrix) manager, patched so it can bind the daemon without waiting on a Zygisk hook inside `system_server`. |
| [`packages/Vector-daemon-patched.apk`](packages/Vector-daemon-patched.apk) | Vector daemon classpath APK. Stock Vector retries a failed `system_server` bridge by **restarting `system_server`**. This build **does not**. It also publishes `vector.manager` on ServiceManager. Drop it in as `/data/adb/modules/zygisk_vector/daemon.apk`. |

## LSPromise vs Vector daemon (simple)

**LSPromise** gets you in. It is the exploit you tap after reboot so KernelSU is in the kernel.

**Vector daemon** runs after you are already in. It is Vector’s background process. The manager app talks to it. If the daemon is down, Vector shows **Not activated**.

## Vector patches

Stock Vector on this device:

1. Talks to `system_server` through a Zygisk binder hook.
2. `system_server` was forked at boot, **before** late-load, so that hook is missing.
3. The daemon then kills `system_server` (`--system-server-max-retry`).
4. The manager waits ~2.5s for a binder and draws **Not activated**.

This tree changes:

- Daemon registers `vector.manager` (`IManagerService`) with ServiceManager.
- Daemon **does not** restart `system_server` when the Zygisk bridge fails (`--system-server-max-retry=0`).
- Manager calls `ServiceManager.getService("vector.manager")` on launch.
- Module `service.sh` starts a **setsid** watchdog so KernelSU late-load can exit without SIGHUP on `vectord`.

Upstream Vector: [JingMatrix/Vector](https://github.com/JingMatrix/Vector) `efb82883` (v2.2 / 3111). Official KernelSU manager: [tiann/KernelSU](https://github.com/tiann/KernelSU) v3.2.5.

## Sources

Vendored under [`src/`](src/):

| Tree | Upstream | Notes |
|------|----------|--------|
| [`src/lspromise`](src/lspromise) | [slapah/lspromise](https://github.com/slapah/lspromise) `9cf09d7` | LSPromise app (userspace + kernel stages). |
| [`src/kernelsu`](src/kernelsu) | [slapah/KernelSU](https://github.com/slapah/KernelSU) branch `kdp-trace` `138b1cf` | LKM + ksud used on this Fold 8. |
| [`src/vector`](src/vector) | [JingMatrix/Vector](https://github.com/JingMatrix/Vector) `efb82883` | Includes the late-load manager/daemon patches below. |

Watchdog scripts used on-device: [`scripts/service.sh`](scripts/service.sh), [`scripts/daemon-watchdog.sh`](scripts/daemon-watchdog.sh).

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
- Vector: GPL-3.0 (upstream). These APKs are modified versions of that work.
- LSPromise: as distributed by its author.

You are responsible for how you use these on hardware you own.
