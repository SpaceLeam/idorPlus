## 2025-12-24 - File Permissions on Sensitive Reports
**Vulnerability:** The application was writing IDOR scan reports (containing sensitive vulnerability data) with `0644` permissions, making them world-readable on shared systems.
**Learning:** Utility functions like `WriteFile` often default to convenient permissions (`0644`) rather than secure ones (`0600`), and these defaults propagate to critical outputs if not carefully reviewed.
**Prevention:** Default to `0600` (user-only read/write) for any file writing utility in security tools. Explicitly review file permissions for any feature that exports sensitive data.
