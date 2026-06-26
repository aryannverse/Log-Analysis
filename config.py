DEFAULT_REGEXES = {
    "HDFS": r"^(\d{6})\s+(\d{6})\s+(\d+)\s+(\w+)\s+([^:]+):\s*(.*)$",
    "APACHE": r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)$",
    "OPENSTACK": r"^(\S+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\d+)\s+(\w+)\s+(\S+)\s+\[([^\]]*)\]\s+(.*)$"
}

DEFAULT_ANOMALIES = {
    "HDFS": {
        "security": ["accesscontrolexception", "unauthorized", "permission denied", "verification failed", "missing", "block"],
        "bug": ["error", "critical", "fatal"]
    },
    "APACHE": {
        "security": ["../", "etc/passwd", "bin/sh", "select", "union", "insert", "drop", "admin"],
        "bug": ["error", "crit", "alert", "emerg"]
    },
    "OPENSTACK": {
        "security": ["unauthorized", "forbidden", "policy check failed", "access denied"],
        "bug": ["error", "critical"]
    }
}
