## 2024-03-24 - Secure File Permissions
**Vulnerability:** Insecure file permissions (0644) used for generated reports and data files.
**Learning:** Default file permissions often allow world-read access. For security tools generating sensitive data, this exposes findings to other users on the system.
**Prevention:** Always use restrictive permissions (0600) for files containing sensitive data or scan results.
