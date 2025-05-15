#!/bin/bash

sudo ./unlink_monitor \ 
-e ".tmp" -e ".tmpfile" -e "~" -e ".swp" -e ".swap" \
  -e ".cache" -e ".thumbnails" -e ".fontconfig" \
  -e "/var/cache/" -e "/usr/share/man/" \
  -e "tmp.i" -e "/var/lib/PackageKit/" \
  -e "/var/lib/update-notifier/" -e "/var/lib/update-manager/" \
  -e ".dpkg-" -e "dpkg-run-stamp" \
  -e "/run/systemd/" -e "/run/NetworkManager/" -e "/run/user/" \
  -e "/proc/" -e "/sys/" -e "/dev/shm/" \
  -e "streams/" -e "inhibit/" -e ".lease" \
  -e ".mozilla/" -e ".chrome/" -e ".config/chrome" -e ".vscode/" \
  -e ".local/share/thumbnail" -e "application_state" \
  -e ".goutputstream-" \
  -e ".git/objects/" -e ".git/logs/" -e "node_modules/" -e ".npm/" \
  -e "__pycache__/" -e ".pyc" -e ".pyo" \
  -e ".log" -e ".journal" -e "/var/log/journal/" \
  -e "/var/log/syslog" -e "/var/log/kern.log" -e "/var/log/dmesg" \
  -e ".sudo_as_admin_successful" -e ".zsh_history" -e ".bash_history" \
  -e "tmp." -T
