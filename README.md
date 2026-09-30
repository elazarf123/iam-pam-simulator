# PAM Just-in-Time Access Simulator

A PowerShell script that simulates the request side of just-in-time (JIT) privileged access: an admin gets temporary elevated access only with a business justification, the grant is time-limited, and every step is written to an audit log.

It's a simulation. It doesn't change any real group memberships or permissions.

## What it does

[`Manage-PrivilegedAccess.ps1`](Manage-PrivilegedAccess.ps1):

1. **Checks for a justification.** If the justification is blank, the request is denied and logged as an `ALERT`.
2. **Grants temporary access** and logs the grant and the justification.
3. **Sets a 60-minute expiry** and logs the time access should be revoked.
4. **Writes a session record** to `Active_PAM_Session.csv` with the account, grant time, expiry, justification, and status.

Log lines use the format `[timestamp] [PAM-LEVEL] message`, and are appended to `PAM_Audit_Trail_20260816.log`.

## Sample output

Audit log:

```text
[2026-08-16 15:20:14] [PAM-SUCCESS] GRANT: Temporary elevated access granted to admin.secops@enterprise.local.
[2026-08-16 15:20:14] [PAM-INFO] JUSTIFICATION: Emergency firewall rule update for incident ticket INC-84920
[2026-08-16 15:20:14] [PAM-WARNING] EXPIRATION: Access token will automatically revoke at 16:20:14.
```

Session record (`Active_PAM_Session.csv`):

| TargetAccount | GrantedAt | ExpiresAt | Justification | SessionStatus |
| :--- | :--- | :--- | :--- | :--- |
| admin.secops@enterprise.local | 2026-08-16 15:20:14 | 16:20:14 | Emergency firewall rule update for incident ticket INC-84920 | Active-Monitored |

Both files in the repo are sample output from test runs.

## Run it

```powershell
git clone https://github.com/elazarf123/iam-pam-simulator.git
cd iam-pam-simulator
powershell -ExecutionPolicy Bypass -File .\Manage-PrivilegedAccess.ps1
```

The account and justification are set at the top of the script (`$AdminUser`, `$Justification`). Clear `$Justification` to see a denied request.

## Concepts shown

- **Zero standing privilege:** elevated rights exist only for an approved, time-boxed session.
- **Justification required:** every grant is tied to a reason, such as an incident ticket.
- **Audit trail:** grants, reasons, and expiry times are logged for review.

## Roadmap

- Take the account, justification, and duration as parameters
- A revocation step that ends expired sessions and logs it
- Optional Active Directory mode that adds and removes a user from a JIT group
