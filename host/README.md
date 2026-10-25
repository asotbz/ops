# host

What runs on nc8kg1101 itself, outside Docker. doco-cd does not deploy any of it (it reads only
`nc8kg1101/`); @jbruns installs it by hand with the runbook below.

- `startup-order.pin`: the pinned release (tag and sha256) of the
  [startup-order](https://github.com/jbruns/homelab-components/tree/main/components/startup-order)
  Custom Component ([ADR 0003](../docs/adr/0003-startup-order-via-systemd-unit.md),
  [ADR 0007](../docs/adr/0007-custom-components-from-homelab-components.md)). Its README covers configuration, exit
  status and logs.
- `startup-order.service`: the systemd unit that runs it. Installed at `/etc/systemd/system/startup-order.service`;
  the script is at `/usr/local/bin/startup-order.sh`, its state and logs in `/var/lib/startup-order/`.

## How it runs

nc8kg1101 is AlmaLinux 9 (systemd 252) with Docker Engine as `docker.service`. The unit is ordered after
`docker.service` and only `Wants=` it, so:

- At boot, once Docker is up, `ExecStart` runs `startup-order.sh start`, which leaves `run` in the background and
  returns. `run` waits for dockerd's own restart-policy starts to settle, stops levels 2 and 3 again, then starts
  every level from 0 to 3, waiting up to 420 s for each to be running and healthy. It logs to `last.log`.
- At shutdown, systemd stops units in reverse order, so `ExecStop` runs `startup-order.sh stop` while Docker is still
  up. It records what is running in `state` and stops it from level 3 down to 0, logging to `shutdown.log`. The next
  boot's `run` starts what was recorded.
- Restarting `docker.service` alone (a package update) leaves the unit alone, and dockerd restarts the containers
  itself, as it does without the unit.

doco-cd (level 3) is restarted by dockerd at boot and may Deploy before `run` steps in; `run` then stops it and
starts it again last.

## Install or upgrade startup-order

@jbruns runs this as `doogie` (sudo) on nc8kg1101; the agent user can only run `docker`. Every step is safe to
re-run. To upgrade, merge the Renovate PR that bumps `startup-order.pin` (Renovate never automerges it) and repeat
steps 1, 2 and 5; repeat step 3 too when the PR changed `startup-order.service`.

1. From a checkout of `main` on your machine, copy the pin and the unit to the Host:

   ```sh
   scp host/startup-order.pin host/startup-order.service doogie@nc8kg1101.asot.bz:
   ssh doogie@nc8kg1101.asot.bz
   ```

2. On the Host, download the pinned release and install it only if its sha256 matches:

   ```sh
   . ./startup-order.pin
   dest=/usr/local/bin/startup-order.sh
   sudo curl -fsSL -o "$dest.new" \
     "https://github.com/jbruns/homelab-components/releases/download/$STARTUP_ORDER_TAG/startup-order.sh"
   echo "$STARTUP_ORDER_SHA256  $dest.new" | sudo sha256sum -c - &&
     sudo chmod 0755 "$dest.new" && sudo mv "$dest.new" "$dest" || sudo rm -f "$dest.new"
   ```

   `sha256sum` prints `OK` on a match. On a mismatch it prints `FAILED`, the download is deleted and the installed
   script is unchanged.

3. Install and enable the unit:

   ```sh
   sudo install -m 0644 -o root -g root startup-order.service /etc/systemd/system/startup-order.service
   sudo systemctl daemon-reload
   sudo systemctl enable startup-order.service
   ```

   Do not `start` it (or `enable --now`): `start` reorders right away, restarting every container at levels 2
   and 3. Enabled, it first runs at the next boot. That boot's shutdown is still dockerd's own, unordered as
   before; every later one is ordered. To cover the next shutdown as well, run `sudo systemctl start
   startup-order.service` in a quiet window (not around the 09:12 Backup): levels 2 and 3 go down for about a
   minute.

4. Check the unit, which changes nothing:

   ```sh
   sudo systemd-analyze verify /etc/systemd/system/startup-order.service   # prints nothing
   systemctl is-enabled startup-order.service                              # enabled
   systemctl show startup-order.service -p Wants -p After -p TimeoutStopUSec # docker.service; 5min
   ```

5. Check what the next boot would do; this changes nothing:

   ```sh
   sudo /usr/local/bin/startup-order.sh plan
   ```

   It lists the levels 2 and 3 containers it would restart and every container by level. A container that shows
   up at level 2 without a label is unlabelled; give it one in its `service.yaml` (or `startup-order=skip` for an
   ad-hoc `docker run`).

## Check it after a reboot

Nothing here needs a reboot; check whenever the Host next reboots:

```sh
systemctl is-active startup-order.service          # active
sudo tail -n 20 /var/lib/startup-order/last.log    # each level "ready", then "run: done"
sudo ls /var/lib/startup-order/state               # absent: every target came up
sudo cat /var/lib/startup-order/shutdown.log       # after an ordered shutdown: "stop: level 3" down to "level 0"
```

A `WARNING level N not ready` means that level timed out and the next one started anyway. If `run` failed it keeps
`state` and exits 1, and what it recorded may still be stopped: find the cause in `last.log`, then run it again in
the foreground with `sudo /usr/local/bin/startup-order.sh run`.

## Roll back

Never `systemctl stop` or `disable --now` the unit to remove it: its stop step stops every container.

```sh
sudo test -e /var/lib/startup-order/state && sudo /usr/local/bin/startup-order.sh run   # start anything left stopped
sudo systemctl disable startup-order.service
sudo rm -f /usr/local/bin/startup-order.sh   # a unit still active until reboot then stops nothing at shutdown
sudo rm -f /etc/systemd/system/startup-order.service && sudo systemctl daemon-reload
sudo rm -rf /var/lib/startup-order
```

Then remove `host/` and its Renovate rules through a PR. dockerd alone restarts the containers at boot again, in no
particular order.
