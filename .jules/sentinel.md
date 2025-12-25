## 2024-05-23 - Insecure File Permissions for Reports
**Vulnerability:** Sensitive scan reports were being written with `0644` (world-readable) permissions.
**Learning:** Default `os.WriteFile` or utility functions often default to `0644`. Security tools handling sensitive data must be explicit about strict permissions.
**Prevention:** Created a centralized `utils.WriteFile` helper with `0600` permissions and enforced its usage across the codebase.
