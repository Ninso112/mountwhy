# mountwhy

mountwhy is a small Linux command-line tool that explains why a mount point is slow or misbehaving. It inspects mount options, free space and inodes, basic reachability for network filesystems, and prints a concise summary of likely issues.

## Features

- Analyzes individual mountpoints or provides an overview of all mounts
- Detects filesystem type (ext4, xfs, nfs, cifs, fuse, etc.)
- Shows mount options (noatime, sync, rw/ro, etc.)
- Checks free space and free inodes using `os.statvfs`
- Performs lightweight network reachability checks for network filesystems
- Identifies common issues:
  - Filesystem nearly full
  - Inodes nearly exhausted
  - Read-only mounts
  - Remote host not reachable
- Human-readable text output with color coding (can be disabled)
- JSON output format for scripting

## Installation

mountwhy requires Python 3 and uses only the Python standard library, so no additional dependencies are needed.

1. Clone or download this repository
2. Make the script executable:
   ```bash
   chmod +x mountwhy.py
   ```
3. Optionally, create a symlink or add to your PATH:
   ```bash
   sudo ln -s $(pwd)/mountwhy.py /usr/local/bin/mountwhy
   ```

Alternatively, you can run it directly with:
```bash
python3 mountwhy.py
```

## Usage

### Analyze a specific mountpoint

Analyze a single mountpoint in detail:

```bash
mountwhy /mnt/data
```

Example output:
```
Mountpoint: /mnt/data
  Device: /dev/sda1
  Type: ext4
  Options: rw,noatime
  Space: 45.2 GB free of 100.0 GB (45.2% free)
  Inodes: 1,234,567 free of 10,000,000 (12.3% free)

Issues:
  - Inodes nearly exhausted (12.3% free)
```

### Overview of mounts with issues

Run without arguments to see a brief overview of mounts that have issues:

```bash
mountwhy
```

This will only show mountpoints that have warnings or problems detected.

### Show all mounts

Use `--all` to see detailed analysis of all mounts:

```bash
mountwhy --all
```

### JSON output

Get structured JSON output for scripting:

```bash
mountwhy --json /mnt/data
```

Example JSON output:
```json
{
  "mountpoint": "/mnt/data",
  "device": "/dev/sda1",
  "fstype": "ext4",
  "options": "rw,noatime",
  "is_network": false,
  "is_readonly": false,
  "accessible": true,
  "space": {
    "total": 107374182400,
    "free": 48516337664,
    "used": 58857844736,
    "percent_free": 45.2
  },
  "inodes": {
    "total": 10000000,
    "free": 1234567,
    "used": 8765433,
    "percent_free": 12.3
  },
  "issues": [
    "Inodes nearly exhausted (12.3% free)"
  ]
}
```

### Disable colored output

Use `--no-color` to disable ANSI color codes:

```bash
mountwhy --no-color /mnt/data
```

This is useful when redirecting output to files or when colors are not supported.

## Understanding the Output

### Common Warnings

#### Filesystem nearly full

Indicates that less than 10% of the filesystem space is free. This can cause performance issues and may prevent new files from being written.

**Example:**
```
Issues:
  - Filesystem nearly full (5.2% free)
```

**Solution:** Free up disk space or expand the filesystem.

#### Inodes nearly exhausted

Indicates that less than 10% of available inodes are free. Even if there's free space, you cannot create new files when inodes are exhausted.

**Example:**
```
Issues:
  - Inodes nearly exhausted (3.1% free)
```

**Solution:** Delete unused files or directories. If the issue persists, consider recreating the filesystem with more inodes.

#### Mount is read-only

The filesystem is mounted read-only, which prevents writing to it. This can be intentional or indicate a filesystem error.

**Example:**
```
Issues:
  - Mount is read-only
```

**Solution:** If this is unexpected, check filesystem logs and consider running `fsck`. Remount as read-write if appropriate.

#### Remote host not reachable

For network filesystems (NFS, CIFS, etc.), indicates that the remote server cannot be reached. This may cause slow performance or timeouts.

**Example:**
```
Issues:
  - Remote host not reachable: DNS resolution failed: [Errno -2] Name or service not known
```

**Solution:** Check network connectivity, DNS configuration, firewall rules, and ensure the remote server is running.

## Limitations

1. **Network reachability checks**: The tool performs lightweight checks (DNS resolution and socket connections) that work without root privileges. However:
   - Firewall rules may block the checks even if the server is reachable
   - Some network filesystems may not respond to simple socket connections
   - The checks do not verify actual filesystem protocol connectivity

2. **Performance analysis**: mountwhy provides basic diagnostics but does not perform deep performance analysis. It focuses on identifying common configuration and capacity issues rather than profiling I/O performance.

3. **Stale mount detection**: The tool can detect when a mountpoint is not accessible, but it does not perform sophisticated stale mount detection (e.g., timeout-based tests).

4. **Platform**: The tool is designed for Linux and relies on `/proc/mounts`. It will not work on other Unix-like systems or Windows.

5. **Permissions**: Some checks may require appropriate permissions. For example, accessing mountpoint statistics may fail if the user lacks read permissions.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See the [LICENSE](LICENSE) file for details.
