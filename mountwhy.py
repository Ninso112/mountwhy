#!/usr/bin/env python3
"""
mountwhy - A Linux CLI tool to diagnose mountpoint issues

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import json
import os
import socket
import sys
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"

# Thresholds
LOW_SPACE_THRESHOLD = 10.0  # Percentage
LOW_INODES_THRESHOLD = 10.0  # Percentage
SOCKET_TIMEOUT = 2  # seconds

# Network filesystem types
NETWORK_FS_TYPES = {
    'nfs', 'nfs4', 'cifs', 'smb', 'smbfs', 'sshfs', 'fuse.sshfs',
    'ncpfs', 'afs', 'ceph', 'glusterfs'
}

# Virtual filesystem types (don't show in overview unless they have real issues)
VIRTUAL_FS_TYPES = {
    'proc', 'sysfs', 'devtmpfs', 'devpts', 'tmpfs', 'cgroup', 'cgroup2',
    'pstore', 'bpf', 'tracefs', 'debugfs', 'securityfs', 'hugetlbfs',
    'mqueue', 'configfs', 'overlay', 'autofs', 'efivarfs', 'binfmt_misc', 'fusectl'
}

# ANSI color codes
COLORS = {
    'reset': '\033[0m',
    'bold': '\033[1m',
    'red': '\033[31m',
    'yellow': '\033[33m',
    'green': '\033[32m',
    'cyan': '\033[36m',
}


def colorize(text: str, color: str, use_color: bool = True) -> str:
    """Add ANSI color codes to text if colors are enabled."""
    if use_color and color in COLORS:
        return f"{COLORS[color]}{text}{COLORS['reset']}"
    return text


def parse_mounts() -> List[Dict[str, str]]:
    """
    Parse /proc/mounts and return list of mount entries.

    Returns:
        List of dictionaries with keys: device, mountpoint, fstype, options
    """
    mounts = []
    mounts_file = '/proc/mounts'

    if not os.path.exists(mounts_file):
        sys.stderr.write(f"Error: {mounts_file} not found. Is this Linux?\n")
        sys.exit(1)

    try:
        with open(mounts_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split()
                if len(parts) < 4:
                    continue

                device = parts[0]
                mountpoint = parts[1].replace('\\040', ' ').replace('\\011', '\t').replace('\\012', '\n')
                fstype = parts[2]
                options = parts[3] if len(parts) > 3 else ''

                mounts.append({
                    'device': device,
                    'mountpoint': mountpoint,
                    'fstype': fstype,
                    'options': options
                })
    except IOError as e:
        sys.stderr.write(f"Error reading {mounts_file}: {e}\n")
        sys.exit(1)

    return mounts


def find_mount(path: str, mounts: List[Dict[str, str]]) -> Optional[Dict[str, str]]:
    """
    Find the mount entry for a given path.

    Args:
        path: Path to check
        mounts: List of mount dictionaries

    Returns:
        Mount dictionary or None if not found
    """
    try:
        canonical_path = os.path.realpath(path)
    except OSError:
        return None

    # Find longest matching mountpoint
    best_match = None
    best_len = 0

    for mount in mounts:
        mountpoint = mount['mountpoint']
        try:
            canonical_mountpoint = os.path.realpath(mountpoint)
        except OSError:
            continue

        if canonical_path == canonical_mountpoint or canonical_path.startswith(canonical_mountpoint + '/'):
            if len(canonical_mountpoint) > best_len:
                best_len = len(canonical_mountpoint)
                best_match = mount

    return best_match


def analyze_mount(mount_entry: Dict[str, str]) -> Dict:
    """
    Analyze a mount entry and gather filesystem statistics.

    Args:
        mount_entry: Mount dictionary with device, mountpoint, fstype, options

    Returns:
        Dictionary with mount information and statistics
    """
    mountpoint = mount_entry['mountpoint']
    fstype = mount_entry['fstype']
    options = mount_entry['options']
    device = mount_entry['device']

    result = {
        'mountpoint': mountpoint,
        'device': device,
        'fstype': fstype,
        'options': options,
        'is_network': is_network_fs(fstype),
        'is_readonly': 'ro' in options.split(','),
        'space_total': 0,
        'space_free': 0,
        'space_used': 0,
        'space_percent_free': 0.0,
        'inodes_total': 0,
        'inodes_free': 0,
        'inodes_used': 0,
        'inodes_percent_free': 0.0,
        'accessible': False,
    }

    # Get filesystem statistics
    try:
        stat = os.statvfs(mountpoint)
        result['accessible'] = True

        # Block size and fragment size (typically the same)
        block_size = stat.f_frsize or stat.f_bsize

        # Space statistics
        result['space_total'] = stat.f_blocks * block_size
        result['space_free'] = stat.f_bavail * block_size  # Available to non-root
        result['space_used'] = result['space_total'] - (stat.f_bfree * block_size)
        if result['space_total'] > 0:
            result['space_percent_free'] = (result['space_free'] / result['space_total']) * 100.0

        # Inode statistics
        result['inodes_total'] = stat.f_files
        result['inodes_free'] = stat.f_favail  # Available to non-root
        result['inodes_used'] = stat.f_files - stat.f_ffree
        if result['inodes_total'] > 0:
            result['inodes_percent_free'] = (result['inodes_free'] / result['inodes_total']) * 100.0

    except OSError as e:
        # Mountpoint not accessible (permission denied, stale mount, etc.)
        result['error'] = str(e)

    return result


def is_network_fs(fstype: str) -> bool:
    """
    Check if filesystem type is a network filesystem.

    Args:
        fstype: Filesystem type string

    Returns:
        True if network filesystem
    """
    # Check exact matches
    if fstype in NETWORK_FS_TYPES:
        return True

    # Check FUSE-based network filesystems
    if fstype.startswith('fuse.') and 'ssh' in fstype.lower():
        return True

    return False


def is_virtual_fs(fstype: str) -> bool:
    """
    Check if filesystem type is a virtual filesystem.

    Args:
        fstype: Filesystem type string

    Returns:
        True if virtual filesystem
    """
    return fstype in VIRTUAL_FS_TYPES


def extract_hostname(device_path: str, fstype: str) -> Optional[str]:
    """
    Extract hostname from network filesystem device path.

    Args:
        device_path: Device path (e.g., "server:/export" for NFS, "//server/share" for CIFS)
        fstype: Filesystem type

    Returns:
        Hostname or None if extraction fails
    """
    if fstype in ('nfs', 'nfs4'):
        # Format: server:/path or server:/path
        if ':' in device_path:
            hostname = device_path.split(':')[0]
            return hostname
    elif fstype in ('cifs', 'smb', 'smbfs'):
        # Format: //server/share
        if device_path.startswith('//'):
            parts = device_path[2:].split('/', 1)
            if parts:
                return parts[0]

    return None


def check_network_reachability(device_path: str, fstype: str) -> Tuple[bool, Optional[str]]:
    """
    Check network reachability for network filesystems.

    Performs DNS resolution and optional socket connection check.
    Works without root privileges.

    Args:
        device_path: Device path containing hostname
        fstype: Filesystem type

    Returns:
        Tuple of (reachable: bool, error_message: Optional[str])
    """
    hostname = extract_hostname(device_path, fstype)
    if not hostname:
        return False, "Could not extract hostname from device path"

    # DNS resolution (works without root)
    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {e}"

    # Attempt socket connection to common ports (non-blocking check)
    ports = {
        'nfs': 2049,
        'nfs4': 2049,
        'cifs': 445,
        'smb': 445,
        'smbfs': 445,
    }

    port = ports.get(fstype)
    if port:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SOCKET_TIMEOUT)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            if result != 0:
                return False, f"Connection to {hostname}:{port} failed (port not open or firewall blocking)"
        except socket.error as e:
            return False, f"Socket error: {e}"

    return True, None


def detect_issues(mount_info: Dict) -> List[str]:
    """
    Detect issues with a mountpoint.

    Args:
        mount_info: Dictionary from analyze_mount()

    Returns:
        List of issue description strings
    """
    issues = []

    if not mount_info.get('accessible', False):
        if 'error' in mount_info:
            issues.append(f"Mountpoint not accessible: {mount_info['error']}")
        else:
            issues.append("Mountpoint not accessible")
        return issues

    # Check space (skip for virtual filesystems with zero space)
    fstype = mount_info.get('fstype', '')
    space_total = mount_info.get('space_total', 0)
    if not (is_virtual_fs(fstype) and space_total == 0):
        space_percent_free = mount_info.get('space_percent_free', 0.0)
        if space_percent_free < LOW_SPACE_THRESHOLD:
            issues.append(f"Filesystem nearly full ({space_percent_free:.1f}% free)")

    # Check inodes (skip for virtual filesystems with zero inodes, and btrfs which doesn't use traditional inodes)
    inodes_total = mount_info.get('inodes_total', 0)
    if not (is_virtual_fs(fstype) and inodes_total == 0) and fstype != 'btrfs':
        inodes_percent_free = mount_info.get('inodes_percent_free', 0.0)
        if inodes_percent_free < LOW_INODES_THRESHOLD:
            issues.append(f"Inodes nearly exhausted ({inodes_percent_free:.1f}% free)")

    # Check read-only
    if mount_info.get('is_readonly', False):
        issues.append("Mount is read-only")

    # Check network reachability (if network FS)
    if mount_info.get('is_network', False):
        reachable, error = check_network_reachability(
            mount_info['device'],
            mount_info['fstype']
        )
        if not reachable:
            issues.append(f"Remote host not reachable: {error}")

    return issues


def format_size(size_bytes: int) -> str:
    """Format bytes to human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def format_output_text(mount_info: Dict, issues: List[str], use_color: bool = True) -> str:
    """
    Format mount information as human-readable text.

    Args:
        mount_info: Dictionary from analyze_mount()
        issues: List of issue strings
        use_color: Whether to use ANSI colors

    Returns:
        Formatted text string
    """
    lines = []
    mountpoint = mount_info['mountpoint']
    fstype = mount_info['fstype']
    device = mount_info['device']

    # Header
    header = f"Mountpoint: {mountpoint}"
    if use_color:
        header = colorize(header, 'bold', use_color)
    lines.append(header)

    # Basic info
    lines.append(f"  Device: {device}")
    lines.append(f"  Type: {fstype}")
    lines.append(f"  Options: {mount_info['options']}")

    if mount_info.get('accessible', False):
        # Space info
        space_free = format_size(mount_info['space_free'])
        space_total = format_size(mount_info['space_total'])
        space_percent = mount_info['space_percent_free']
        space_line = f"  Space: {space_free} free of {space_total} ({space_percent:.1f}% free)"
        if space_percent < LOW_SPACE_THRESHOLD and use_color:
            space_line = colorize(space_line, 'red', use_color)
        lines.append(space_line)

        # Inode info
        inodes_free = mount_info['inodes_free']
        inodes_total = mount_info['inodes_total']
        inodes_percent = mount_info['inodes_percent_free']
        inodes_line = f"  Inodes: {inodes_free:,} free of {inodes_total:,} ({inodes_percent:.1f}% free)"
        if inodes_percent < LOW_INODES_THRESHOLD and use_color:
            inodes_line = colorize(inodes_line, 'red', use_color)
        lines.append(inodes_line)
    else:
        error_msg = mount_info.get('error', 'Unknown error')
        error_line = f"  Error: {error_msg}"
        if use_color:
            error_line = colorize(error_line, 'red', use_color)
        lines.append(error_line)

    # Issues
    if issues:
        lines.append("")
        issues_header = "Issues:"
        if use_color:
            issues_header = colorize(issues_header, 'yellow', use_color)
        lines.append(issues_header)
        for issue in issues:
            issue_line = f"  - {issue}"
            if use_color:
                issue_line = colorize(issue_line, 'yellow', use_color)
            lines.append(issue_line)
    else:
        if mount_info.get('accessible', False):
            ok_line = "Status: OK"
            if use_color:
                ok_line = colorize(ok_line, 'green', use_color)
            lines.append("")
            lines.append(ok_line)

    return "\n".join(lines)


def format_output_json(mount_info: Dict, issues: List[str]) -> str:
    """
    Format mount information as JSON.

    Args:
        mount_info: Dictionary from analyze_mount()
        issues: List of issue strings

    Returns:
        JSON string
    """
    output = {
        'mountpoint': mount_info['mountpoint'],
        'device': mount_info['device'],
        'fstype': mount_info['fstype'],
        'options': mount_info['options'],
        'is_network': mount_info['is_network'],
        'is_readonly': mount_info['is_readonly'],
        'accessible': mount_info.get('accessible', False),
        'space': {
            'total': mount_info.get('space_total', 0),
            'free': mount_info.get('space_free', 0),
            'used': mount_info.get('space_used', 0),
            'percent_free': mount_info.get('space_percent_free', 0.0),
        },
        'inodes': {
            'total': mount_info.get('inodes_total', 0),
            'free': mount_info.get('inodes_free', 0),
            'used': mount_info.get('inodes_used', 0),
            'percent_free': mount_info.get('inodes_percent_free', 0.0),
        },
        'issues': issues,
    }

    if 'error' in mount_info:
        output['error'] = mount_info['error']

    return json.dumps(output, indent=2)


def print_overview(mounts: List[Dict[str, str]], json_output: bool, use_color: bool):
    """
    Print brief overview of all mounts with warnings.

    Args:
        mounts: List of mount dictionaries
        json_output: Whether to output JSON format
        use_color: Whether to use colors
    """
    results = []

    for mount in mounts:
        mount_info = analyze_mount(mount)
        issues = detect_issues(mount_info)

        # Filter out virtual filesystems with zero space/inodes (normal for them)
        if is_virtual_fs(mount_info['fstype']):
            # Only show virtual FS if it has real accessibility issues
            if mount_info.get('accessible', False):
                # Skip virtual filesystems with zero space (normal)
                if mount_info.get('space_total', 0) == 0 and mount_info.get('inodes_total', 0) == 0:
                    continue

        # In overview mode, only show mounts with issues
        if issues or not mount_info.get('accessible', False):
            results.append((mount_info, issues))

    if json_output:
        json_results = []
        for mount_info, issues in results:
            json_results.append({
                'mountpoint': mount_info['mountpoint'],
                'device': mount_info['device'],
                'fstype': mount_info['fstype'],
                'issues': issues,
            })
        print(json.dumps(json_results, indent=2))
    else:
        if not results:
            print("No mounts with issues found.")
            return

        for mount_info, issues in results:
            print(format_output_text(mount_info, issues, use_color))
            print()


def print_all_mounts(mounts: List[Dict[str, str]], json_output: bool, use_color: bool):
    """
    Print detailed analysis of all mounts.

    Args:
        mounts: List of mount dictionaries
        json_output: Whether to output JSON format
        use_color: Whether to use colors
    """
    if json_output:
        json_results = []
        for mount in mounts:
            mount_info = analyze_mount(mount)
            issues = detect_issues(mount_info)
            json_results.append({
                'mountpoint': mount_info['mountpoint'],
                'device': mount_info['device'],
                'fstype': mount_info['fstype'],
                'options': mount_info['options'],
                'is_network': mount_info['is_network'],
                'is_readonly': mount_info['is_readonly'],
                'accessible': mount_info.get('accessible', False),
                'space': {
                    'total': mount_info.get('space_total', 0),
                    'free': mount_info.get('space_free', 0),
                    'percent_free': mount_info.get('space_percent_free', 0.0),
                },
                'inodes': {
                    'total': mount_info.get('inodes_total', 0),
                    'free': mount_info.get('inodes_free', 0),
                    'percent_free': mount_info.get('inodes_percent_free', 0.0),
                },
                'issues': issues,
            })
        print(json.dumps(json_results, indent=2))
    else:
        for mount in mounts:
            mount_info = analyze_mount(mount)
            issues = detect_issues(mount_info)
            print(format_output_text(mount_info, issues, use_color))
            print()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze Linux mountpoints to diagnose filesystem issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  mountwhy /mnt/data              Analyze specific mountpoint
  mountwhy                        Show overview of mounts with issues
  mountwhy --all                  Show detailed analysis of all mounts
  mountwhy --json /mnt/data       Output in JSON format
  mountwhy --no-color /mnt/data   Disable colored output
        """
    )

    parser.add_argument(
        'mountpoint',
        nargs='?',
        help='Mountpoint path to analyze (if omitted, shows overview of mounts with issues)'
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Show detailed analysis of all mounts'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Output in JSON format'
    )

    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    args = parser.parse_args()

    use_color = not args.no_color

    # Read mounts
    try:
        mounts = parse_mounts()
    except SystemExit:
        sys.exit(1)

    # Handle different modes
    if args.mountpoint:
        # Analyze specific mountpoint
        mount_entry = find_mount(args.mountpoint, mounts)
        if not mount_entry:
            sys.stderr.write(f"Error: {args.mountpoint} is not a mountpoint\n")
            sys.exit(1)

        mount_info = analyze_mount(mount_entry)
        issues = detect_issues(mount_info)

        if args.json:
            print(format_output_json(mount_info, issues))
        else:
            print(format_output_text(mount_info, issues, use_color))

    elif args.all:
        # Show all mounts in detail
        print_all_mounts(mounts, args.json, use_color)

    else:
        # Overview mode: show only mounts with issues
        print_overview(mounts, args.json, use_color)


if __name__ == '__main__':
    main()
