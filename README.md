# SSH Toggle

On-demand SSH for Windows. **One click turns SSH on. Closing it turns SSH off.**
While it is on, a live dashboard shows the connect command, who is connected, and every login attempt.

```
  ==============================================================
   SSH IS ON   |  press Q or Ctrl+C to turn SSH OFF
  ==============================================================

   Connect from your other device:
       ssh Luthfi@192.168.1.4

   Login     : SSH KEY ONLY (password login disabled)
   Users     : only Luthfi may log in
   Firewall  : TCP 22 open to [LocalSubnet] only
   Started   : 10:20:11   (on for 3 min)
  --------------------------------------------------------------
   CONNECTED NOW (1)
       Luthfi           from 192.168.1.12:64827   since 10:35:42
  --------------------------------------------------------------
   RECENT ACTIVITY   (failed logins: 0, blocked IPs: 0)
       10:35:43  LOGIN OK      Luthfi from 192.168.1.12 (publickey)
```

(The screen above is an illustration of the layout, not a captured screenshot.)

## Contents

- [Why](#why)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Connecting from another device](#connecting-from-another-device)
- [Parameters](#parameters)
- [What it changes on your machine](#what-it-changes-on-your-machine)
- [Security model](#security-model)
- [Troubleshooting](#troubleshooting)
- [Undoing everything](#undoing-everything)
- [Known limitations](#known-limitations)
- [What has and has not been tested](#what-has-and-has-not-been-tested)

## Why

An SSH server that is always running is an always-open door. This tool keeps the door shut and only opens it while you are actually using it, for a limited set of devices, with hardened settings, and it tells you who walked in.

## Requirements

- Windows 10 (1809+), Windows 11, or Windows Server 2019+.
- Administrator rights (the script asks for them through the normal UAC prompt).
- OpenSSH Server. If it is missing, the script tries to install it (needs internet).
- Windows PowerShell 5.1 (built in) or PowerShell 7.
- The *other* device only needs an SSH client (macOS, Linux, Windows, iOS/Android apps).

This is a Windows-only tool. For macOS or Linux hosts use their built-in Remote Login / sshd.

## Quick start

1. Put the folder somewhere permanent (for example `D:\SSH-Toggle`).
2. Optional, once: create a Desktop shortcut. Always go through the launcher: running the `.ps1` directly is blocked by Windows' default script policy.
   ```bat
   SSH-Toggle.bat -CreateShortcut
   ```
3. Double-click **SSH Toggle** (or `SSH-Toggle.bat`) and approve the UAC prompt.
4. Run the `ssh ...` command shown on screen from your other device.
5. Press **Q** or **Ctrl+C** in the window when you are done. SSH is turned off.

Extra options can be passed to the launcher, for example:

```bat
SSH-Toggle.bat -AllowedRemote 192.168.1.12
```

### Use SSH keys (recommended)

When a usable SSH key is installed for the target user, the script automatically disables password login.

On the other device:

```bash
ssh-keygen -t ed25519            # skip if you already have a key
cat ~/.ssh/id_ed25519.pub        # copy this line
```

On Windows, add that line to the right file:

| Target user is... | Key file |
|---|---|
| In the Administrators group | `C:\ProgramData\ssh\administrators_authorized_keys` |
| A standard user | `C:\Users\<name>\.ssh\authorized_keys` |

OpenSSH ignores key files that other users can modify. For the administrators file, set strict permissions (elevated PowerShell):

```powershell
icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant "SYSTEM:F" /grant "BUILTIN\Administrators:F"
```

If the file exists but its permissions look wrong, the script keeps password login enabled and shows a warning, so a bad key file cannot lock you out.

## Connecting from another device

```bash
ssh <user>@<ip-shown-in-the-window>
ssh -p 2222 <user>@<ip>          # only if you changed -Port
```

You get a shell on the Windows machine. The default SSH shell on Windows is `cmd.exe`; type `powershell` to switch, or run a command directly:

```bash
ssh <user>@<ip> powershell -NoProfile -Command "Get-Service sshd"
```

**Important:** if the target user is an administrator, the SSH session runs with **full administrator rights** and there is no UAC prompt over SSH. Whoever holds the private key can do anything on the machine. Protect the key like a password: disk encryption and a login password on the device that holds it, and never copy it around.

## Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `-Port` | `22` | TCP port for SSH. |
| `-AllowedRemote` | `LocalSubnet` | Who may reach the port while SSH is on. `LocalSubnet` = same LAN/Wi-Fi. Safest: one device, e.g. `192.168.1.12`. Also accepts `192.168.1.0/24`, ranges, and comma-separated lists. |
| `-AllowInternet` | off | Required if `-AllowedRemote` is `Any` (every address). Not recommended. |
| `-MaxFailures` | `5` | Block a remote IP after this many failed logins during the session. `0` turns it off. |
| `-KeepPasswordLogin` | off | Do not disable password login even if a usable key exists. |
| `-AllowAnyUser` | off | Do not restrict SSH logins to the target user. |
| `-TargetUser` | current user | The Windows account that will log in. |
| `-CreateShortcut` | | Create a Desktop shortcut for the current user, then exit. |
| `-LockFolder` | | Make the script folder writable by administrators only, then exit (see [Security model](#security-model)). |
| `-Revert` | | Remove everything the script added and restore saved settings, then exit. |
| `-TestSeconds` | `0` | Testing only: stop automatically after N seconds. |

## What it changes on your machine

**While SSH is on**

| What | Change |
|---|---|
| Service `sshd` | Started. |
| Firewall rule `SSH-Toggle-Inbound` | Created: inbound, TCP, the SSH port, only `sshd.exe`, only the addresses in `-AllowedRemote`, all profiles. |
| Firewall rule `OpenSSH-Server-In-TCP` (built in) | Disabled, because it is open to every address. |
| `C:\ProgramData\ssh\sshd_config` | A marked block is added at the top (see below). A one-time backup is kept as `sshd_config.bak-ssh-toggle`. |

The block looks like this (the last three lines depend on your setup):

```
# >>> SSH-Toggle managed block (do not edit by hand) >>>
Port 22
MaxAuthTries 3
LoginGraceTime 30
PermitEmptyPasswords no
ClientAliveInterval 60
ClientAliveCountMax 3
PasswordAuthentication no          # only when a usable key exists
AuthenticationMethods publickey    # only when a usable key exists
AllowUsers Luthfi luthfi           # unless -AllowAnyUser
# <<< SSH-Toggle managed block <<<
```

The edit is validated with `sshd -t`; if sshd rejects it, the original file is put back.

**When SSH is turned off** (Q, Ctrl+C, or the window closing)

- `sshd` is stopped and any remaining SSH sessions are killed.
- `SSH-Toggle-Inbound` and any `SSH-Toggle-Block-*` rules are deleted.
- The built-in OpenSSH rule stays disabled.

**Persistent changes (kept after SSH is off)**

- `sshd` startup type is set to **Manual**, so it never starts by itself at boot.
- The hardening block stays in `sshd_config` (it is harmless while sshd is stopped, and is refreshed on every run).
- `C:\ProgramData\SSH-Toggle\original-state.json` records the settings the script first saw, so `-Revert` can restore them.

## Security model

What the script does to keep the machine safe:

- **Closed by default.** The port is open and sshd runs only while the window is open.
- **Narrow firewall rule.** Limited to `sshd.exe` and to the addresses you choose. `-AllowedRemote Any` is refused unless you add `-AllowInternet`.
- **Key-only login** when a usable key exists, enforced with `AuthenticationMethods publickey` (this also removes keyboard-interactive, which stays enabled if you only set `PasswordAuthentication no`).
- **Single account.** `AllowUsers` restricts logins to the target user, so other local accounts cannot log in over SSH. On Windows the match is not case-sensitive.
- **Brute-force limits.** 3 authentication tries per connection, 30-second login grace time, and automatic IP blocking after `-MaxFailures` failed logins. Loopback and the machine's own addresses are never blocked. Blocks last until SSH is turned off.
- **Hostile text is neutralised.** Usernames in the log come from remote clients. Control and escape characters are replaced before anything is printed, and log patterns are anchored to the start of the message so a crafted username cannot fake a successful login.
- **No profile code runs as admin.** The elevated process is started with `-NoProfile`, and with the full path to Windows PowerShell.
- **Input is validated** before elevation (addresses, quotes in parameters).
- **Safe config edits.** A damaged or old marker block can never cause the rest of `sshd_config` to be deleted.

### Lock the script folder (recommended)

The script runs as administrator. If a normal program can modify the script file, it can gain admin rights the next time you approve the UAC prompt. Check the folder: the dashboard shows a warning if non-admin programs can write to it.

To fix it, run once:

```bat
SSH-Toggle.bat -LockFolder
```

This makes administrators the owner and the only ones who can write; everyone else can read and run. Afterwards, editing the script requires an elevated editor. `-LockFolder` refuses to run if the folder contains files other than `SSH-Toggle.ps1`, `SSH-Toggle.bat` and `README.md`, so it never changes permissions on unrelated files. Keep the script in its own folder.

### Things to be aware of

- **Public Wi-Fi.** `LocalSubnet` means "everyone on this network". On shared Wi-Fi use `-AllowedRemote <your device IP>`. The dashboard warns when the network is marked Public.
- **Passwords.** Without a usable key, SSH falls back to Windows account passwords. Use a long password, or install a key.
- **`-ExecutionPolicy Bypass`.** The launcher bypasses PowerShell's script policy for this one script. That is why you should lock the folder.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `Operation timed out` from the other device | Packets are being dropped. Check that both devices are on the same network, that the script's window is open, and that no third-party firewall is blocking port 22. The dashboard lists a third-party firewall when it detects one. **Antivirus firewalls (Avast, for example) often block inbound traffic independently of Windows Firewall.** Allow TCP 22 there or disable its firewall component. |
| `Connection refused` | Nothing is listening. SSH is off, or the port differs from the one you used (`-p`). |
| `Permission denied (publickey)` | Your public key is not in the key file for that user, or the key file has loose permissions. See [Use SSH keys](#use-ssh-keys-recommended). |
| `Permission denied` and the dashboard shows `DENIED` | The user is not the target user. Connect as the target user, or run with `-AllowAnyUser`. |
| Connected, but locked out after changing keys | Run `-Revert`, or start with `-KeepPasswordLogin` to allow passwords for a moment. |
| Window shows `ERROR` | Read the message. Common ones: OpenSSH Server could not be installed (install it manually), or sshd did not start listening within 15 seconds (check Event Viewer > Applications and Services Logs > OpenSSH > Operational). |
| Antivirus quarantines the script | Heuristic engines can flag scripts that change firewall and service settings. Check the script yourself, then add an exception for **this folder only** (never for `powershell.exe`). |
| SSH still running after closing the window | Closing with the X button is best-effort. Run the script again and press Q, or run `-Revert`. |

## Undoing everything

```bat
SSH-Toggle.bat -Revert
```

This stops sshd, deletes the script's firewall rules, removes the hardening block from `sshd_config`, and restores the sshd startup type and the built-in firewall rule to what the script first saw (from `original-state.json`). If that file does not exist, startup type and the built-in rule are left as they are. `Revert` refuses to run while SSH Toggle is active in another window.

To uninstall completely: run `-Revert`, then delete the folder, the Desktop shortcut and `C:\ProgramData\SSH-Toggle\`. The backup `sshd_config.bak-ssh-toggle` can be deleted too.

## Known limitations

- The "original state" is captured the **first time** the script runs on a machine. If the machine's SSH settings were changed by hand before that, `-Revert` restores the already-changed values.
- Closing the window with the X button is best-effort. If the process is killed (for example from Task Manager), SSH may stay on. Startup type is Manual, so it will not survive a reboot.
- Only one instance can run at a time.
- Blocked IPs are not remembered between sessions.
- Windows 10 before 1809 has no OpenSSH Server capability. Install the Win32-OpenSSH package manually.
- Logins by users that exist in a domain, or Microsoft accounts with unusual names, were not tested. If `AllowUsers` does not match your account format, use `-AllowAnyUser`.

## What has and has not been tested

Tested on Windows 11 with Windows PowerShell 5.1:

- Turning SSH on and off, including automatic shutdown, with the firewall rule, `sshd` state and processes cleaned up afterwards.
- The server offers only `publickey`; accounts not in `AllowUsers` are rejected.
- Hardening block creation, replacement of older blocks, and `-Revert` restoring `sshd_config` byte for byte.
- `-LockFolder` on a copy of the folder: a non-admin process could not create, modify, rename or re-permission files.
- Firewall rule scoping, and creation and removal of the auto-block rule.
- Log parsing, injection attempts, escape-sequence sanitising, failure counting, auto-block thresholds and the dashboard, using real log lines and simulated data.

Not tested:

- A real login from another device with the current version (an earlier version of the script was confirmed working from a Mac).
- Auto-blocking against a real attacker.
- Windows 10, Windows Server, PowerShell 7, non-English Windows, and domain-joined machines.
- Closing the window with the X button.

## Files

| File | Purpose |
|---|---|
| `SSH-Toggle.ps1` | The script. |
| `SSH-Toggle.bat` | Launcher; passes extra arguments through. |
| `README.md` | This file. |
