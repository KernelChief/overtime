# ⏱️ overtime

### A self-hosted overtime hour bank for freelancers, consultants, or employees.

[![Made with Python](https://img.shields.io/badge/Made%20with-Python-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Platform](https://img.shields.io/badge/Platform-Proxmox%20LXC%20%2F%20AlmaLinux-E95420)](https://www.proxmox.com/)
[![Tests](https://img.shields.io/badge/Tests-pytest-0A9EDC?logo=pytest&logoColor=white)](tests/)
[![Buy Me A Coffee](https://img.shields.io/badge/Support-Buy%20Me%20A%20Coffee-orange?logo=buy-me-a-coffee)](https://buymeacoffee.com/ttheroux)

Banks extra hours against one or more clients/employers and keeps a dead-simple ledger: bank
hours in, use them later, split by company, never go negative. Flask + SQLite, no external
dependencies.

Each user has their own bank, split by company. Admins manage users and the email server under
Settings.

![Login screen](docs/screenshots/login.jpg)

One-line install onto a Proxmox LXC container, using the `ct/` / `install/` / `misc/` scripts
in this repo.

---

## ⚠️ Backups Are on You

This app stores everything in one SQLite file, outside the repo, inside your container. **It
is not responsible for lost data**: there is no cloud backup, no undo for a deleted entry, and
no safety net beyond whatever backup strategy you set up yourself.

**Back up `/var/lib/overtime/overtime.db` regularly**, a Proxmox snapshot of the container, a
cron job that copies the file somewhere else, whatever fits your setup. Do this before every
update too, just in case.

---

## 📚 Quick Navigation

- [⚠️ Backups Are on You](#️-backups-are-on-you)
- [✨ Features](#-features)
- [🚀 Quick Start: Self-Hosted LXC Container](#-quick-start-self-hosted-lxc-container)
- [🔄 Updating the Deployed Container](#-updating-the-deployed-container)
- [👤 Accounts](#-accounts)
  - [First run](#first-run)
  - [Adding more accounts](#adding-more-accounts)
  - [Signing in](#signing-in)
  - [Forgot a password](#forgot-a-password)
  - [Completely locked out](#completely-locked-out)
- [💾 Data](#-data)
- [🧰 Troubleshooting](#-troubleshooting)
- [🗺️ Roadmap](#️-roadmap)

---

## ✨ Features

- Multi-company hour bank per user: a separate, named balance for each client/employer
- Bank / Use entries with notes, edit and delete, CSV/JSON export
- Multi-user with admin user management and email-based password resets
- A balance can't go negative: you can't use more hours than you've banked for that company

---

## 🚀 Quick Start: Self-Hosted LXC Container

For Proxmox users who want it running centrally and reachable by a team. Run this on the
**Proxmox host** (not inside a container):

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/KernelChief/overtime/main/ct/overtime.sh)"
```

> **What this does:** creates a new unprivileged AlmaLinux LXC container, picking a free
> container ID and your active storage automatically; boots it and waits for networking;
> installs git + Python inside it, clones this repo, and sets up a venv; then creates and
> starts a systemd service for the app, plus an `update` command for later.

When it finishes, it prints the container ID and the URL to open
(`http://<container-ip>:8080`). Making that reachable outside the container, Cloudflare
Tunnel, a port-forward, Nginx Proxy Manager, whatever fits your setup, is up to you; the
script doesn't do that part.

The install scripts (`ct/`, `install/`, `misc/`) live in this repo so the one-liner above is
self-contained: anyone running it only needs this repo, not access to any private
infrastructure.

### Options

Set these as environment variables before the `bash -c "..."` call, e.g.
`CORES=2 RAM=512 bash -c "..."`. Everything below is optional, sensible defaults are used if
you skip it.

| Variable | Default | What it controls |
|---|---|---|
| `CTID` | next free ID | Container ID to create (or adopt, with `ADOPT=1`) |
| `CT_HOSTNAME` | `overtime` | Hostname of the container |
| `CORES` | `1` | CPU cores |
| `RAM` | `256` | Memory in MB |
| `DISK` | `3` | Root disk size in GB |
| `STORAGE` | auto-picked | Storage for the container's root disk |
| `TEMPLATE_STORAGE` | auto-picked | Storage for the AlmaLinux template |
| `BRIDGE` | `vmbr0` | Network bridge |
| `VLAN` | none | VLAN tag, if your network needs one |
| `STATIC_IP` + `GATEWAY` | DHCP | Set both together for a static IP, e.g. `STATIC_IP=10.0.0.50/24 GATEWAY=10.0.0.1` |
| `ALMA_VER` | latest available | AlmaLinux major version |
| `FEATURES` | `nesting=1` | LXC features passed to `pct create` |
| `APP_BRANCH` | `main` | Branch of this app's repo to install |
| `SCRIPTS_BRANCH` | `main` | Branch of the install scripts themselves |
| `GIT_HOST` + `GIT_USER` | GitHub / `KernelChief` | Install from a different git host or account, e.g. your own fork |
| `AUTO_UPDATE` | `0` | Set to `1` to check for updates automatically inside the container |
| `INTERVAL` | `1h` | How often, when `AUTO_UPDATE=1` |
| `GIT_AUTH_USER` + `GIT_TOKEN` | none | Only needed if the app repo is private |
| `ADOPT` + `CTID` | off | Point an **existing** container at this installer instead of creating a new one, e.g. `ADOPT=1 CTID=121 bash -c "..."` |

---

## 🔄 Updating the Deployed Container

After pushing a change to this repo, pull it into the running container with:

```bash
pct exec <ctid> -- update
```

Or, from inside the container's own console, just run:

```bash
update
```

> **What this does:** pulls the latest code from this repo and restarts the app inside the
> container, only if Python code or `requirements.txt` changed, and it automatically rolls
> back if the new version fails to start. It does **not** touch
> `/var/lib/overtime/overtime.db`: every bank and entry is untouched by an update.

Turn on automatic, periodic updates at install time with `AUTO_UPDATE=1` (see the
[options table](#options) above). Check what the updater has done with:

```bash
pct exec <ctid> -- journalctl -t app-update -n 20
```

---

## 👤 Accounts

### First Run

On an empty database, the app asks you to create the admin account before anything else:

1. Open the app in a browser.
2. You're redirected to **Create the admin account**.
3. Enter a username and a password.
4. You're signed in as the admin.

### Adding More Accounts

Only admins can add accounts. As an admin:

1. Go to **Settings**.
2. Click **Manage users**.
3. Fill in a username, an optional email (needed only if that person wants password resets by
   email), and a password, then **Add user**.
4. Share the password with them directly; they can change it themselves under Settings.

> Each new user gets their own hour bank. From the same **Manage users** page, an admin can
> also: make or remove an admin, reset anyone's password, disable (and re-enable) an account.

> **Guardrail:** the app always keeps at least one enabled admin. You can't demote, disable,
> or delete the only admin, make someone else an admin first.

### Signing In

Sign in with your **username or your email**, whichever you have on hand.

### Forgot a Password

This only works once an admin has configured an email server:

1. An admin goes to **Settings**, fills in the SMTP host, port, security type, and a "send
   from" address, then saves it.
2. The admin can click **Send a test email** to confirm it actually works.
3. Once that's saved, the sign-in page shows a **Forgot password?** link for everyone.
4. Clicking it emails a 6-digit code to the address on that account. The code works for
   **10 minutes** before it's rejected.

### Completely Locked Out

No working account, no email configured, or the email server itself is unreachable: recover
from the container's own console:

```bash
python app.py setpw <username>
```

> **What this does:** sets a new password for that user, re-enables the account, and makes it
> an admin, so the console can always get you back in, even if every account is currently
> disabled.

---

## 💾 Data

Everything lives outside this repo, in `/var/lib/overtime/overtime.db` inside the container.
Pushing code here, or running an update, never touches it. See
[⚠️ Backups Are on You](#️-backups-are-on-you) above: that file is the only copy unless you
make one yourself.

| What's in the database | Scope |
|---|---|
| Companies, bank/use entries | Per-user, each user has their own banks |
| User accounts (username, password, email, admin flag) | Per-account |
| App settings (idle timeout, SMTP server) | Shared, admin-configured, applies to everyone |

---

## 🧰 Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| App won't load after install | `pct exec <ctid> -- journalctl -u overtime -n 50` |
| Stuck on **Create the admin account** after an update | Expected only on a brand-new, empty database. If this happens on an install that already had data, something deleted the DB file: check `/var/lib/overtime/overtime.db` exists in the container. |
| **Forgot password?** link doesn't show on the sign-in page | No admin has saved a working email server yet under Settings. |
| Reset email never arrives | Use **Send a test email** under Settings to check the SMTP settings on their own; also check the account actually has an email address saved. |
| Locked out of every account | Use `python app.py setpw <username>` from the container console, see [Completely Locked Out](#completely-locked-out). |
| "Too many attempts" on sign-in or reset | Several wrong tries within a few minutes locks that IP out temporarily. Wait a few minutes and try again. |
| Update seems stuck or reverted | `pct exec <ctid> -- journalctl -t app-update -n 20`, a failed update automatically rolls back and won't be retried until you push something different. |

---

## 🗺️ Roadmap

- [x] Public AlmaLinux LXC script, see `ct/`
- [x] pytest suite covering accounts, companies/entries, and the hour-bank guard rails, see `tests/`
- [ ] CI: lint + the test suite on push
