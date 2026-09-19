savedcmd_/src/selinux_off.mod := printf '%s\n'   selinux_off.o | awk '!x[$$0]++ { print("/src/"$$0) }' > /src/selinux_off.mod
