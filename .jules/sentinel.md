## 2024-05-23 - Secure File Permissions
**Vulnerability:** File permission exposure (CWE-732)
**Learning:** `os.WriteFile` defaults to the permissions provided, which were `0644` (world-readable), exposing sensitive security reports.
**Prevention:** Enforce `0600` permissions (owner-only) for all sensitive file outputs via a centralized `WriteFile` utility.
