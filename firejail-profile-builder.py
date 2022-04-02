#!/usr/bin/python3
# SPDX-License-Identifier: ISC

# Copyright © 2022 rusty-snake
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

from __future__ import annotations

import argparse
import enum
import os
import os.path
import re
import shlex
import subprocess
import sys
import tempfile
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Callable, Optional, Union


class Inc:
    def __init__(self, path: Union[Path, str], command: Optional[str] = None):
        self.path = Path(path)
        if command:
            self.command = command + " "
        else:
            if self.path.name.startswith("disable-"):
                self.command = "blacklist "
            elif self.path.name.startswith("whitelist-"):
                self.command = "whitelist "
            else:
                raise Exception(f"command must be specified for {self.path.name}")
        self._list: Optional[list[Path]] = None

    @property
    def list(self) -> list[Path]:
        if self._list is None:
            with open(self.path) as raw_list:
                self._list = [
                    Path(
                        line[len(self.command) :]
                        .strip()
                        .replace("${HOME}", str(HOME))
                        .replace("${RUNUSER}", str(RUNUSER))
                    )
                    for line in raw_list
                    if line.startswith(self.command)
                ]
        return self._list

    def __iter__(self) -> Iterator[Path]:
        return iter(self.list)

    def __contains__(self, path: Union[Path, str]) -> bool:
        return Path(path) in self.list

    def affects(self, path: Union[Path, str]) -> bool:
        """Retruns True if self accets path"""
        path = Path(path)
        return path in self or any(p in path.parents for p in self)


WHITELIST_COMMON = Inc("/etc/firejail/whitelist-common.inc")
WHITELIST_RUN_COMMON = Inc("/etc/firejail/whitelist-run-common.inc")
WHITELIST_RUNUSER_COMMON = Inc("/etc/firejail/whitelist-runuser-common.inc")
WHITELIST_USR_SHARE_COMMON = Inc("/etc/firejail/whitelist-usr-share-common.inc")
WHITELIST_VAR_COMMON = Inc("/etc/firejail/whitelist-var-common.inc")

DISABLE_COMMON = Inc("/etc/firejail/disable-common.inc")
DISABLE_PROGRAMS = Inc("/etc/firejail/disable-programs.inc")

MDWE_SYSCALLS = (
    "mmap",
    "mmap2",
    "mprotect",
    "pkey_mprotect",
    "memfd_create",
    "shmat",
)

PRIVATE_ETC_TEMPLATES = {
    "Common": {
        "alternatives",
        "ld.so.cache",
        "ld.so.conf",
        "ld.so.conf.d",
        "ld.so.preload",
        "locale",
        "locale.alias",
        "locale.conf",
        "localtime",
        "mime.types",
        "xdg",
    },
    "Common-Extra": {
        "group",
        "magic",
        "magic.mgc",
        "passwd",
    },
    "3D": {
        "bumblebee",
        "drirc",
        "glvnd",
        "nvidia",
    },
    "Audio": {
        "alsa",
        "asound.conf",
        "machine-id",
        "pulse",
    },
    "D-Bus": {
        "dbus-1",
        "machine-id",
    },
    "GUI": {
        "fonts",
        "pango",
        "X11",
    },
    "GTK": {
        "dconf",
        "gconf",
        "gtk-2.0",
        "gtk-3.0",
    },
    "KDE": {
        "kde4rc",
        "kde5rc",
    },
    "Networking": {
        "ca-certificates",
        "crypto-policies",
        "host.conf",
        "hostname",
        "hosts",
        "nsswitch.conf",
        "pki",
        "protocols",
        "resolv.conf",
        "rpc",
        "services",
        "ssl",
    },
    "Networking-Extra": {
        "gai.conf",
        "proxychains.conf",
    },
    "Qt": {
        "Trolltech.conf",
    },
}

HOME = Path.home()
RUNUSER = Path(f"/run/user/{os.getuid()}")


class Protocol(enum.Enum):
    """All protocols supported by firejail's protocol filter"""

    AF_UNIX = 1
    AF_INET = 2
    AF_INET6 = 10
    AF_NETLINK = 16
    AF_PACKET = 17
    AF_BLUETOOTH = 31

    @staticmethod
    def from_str(s: str) -> Protocol:
        """Creates a Protocol from a str"""
        if s == "AF_UNIX":
            return Protocol.AF_UNIX
        if s == "AF_INET":
            return Protocol.AF_INET
        if s == "AF_INET6":
            return Protocol.AF_INET6
        if s == "AF_NETLINK":
            return Protocol.AF_NETLINK
        if s == "AF_PACKET":
            return Protocol.AF_PACKET
        if s == "AF_BLUETOOTH":
            return Protocol.AF_BLUETOOTH
        raise ValueError("Not a Protocol")


class AccessKind(enum.Enum):
    """Possible access kinds"""

    CREAT = enum.auto()
    EXEC = enum.auto()
    OPEN = enum.auto()
    STAT = enum.auto()


class FirejailProfileBuilder:
    def __init__(self, program: str, arguments: list[str], firejail_cmd: str):
        self.program = program
        self.arguments = arguments
        self.firejail_cmd = firejail_cmd

        self.strace_output: Optional[str] = None
        self.paths: defaultdict[Path, set[AccessKind]] = defaultdict(set)
        self.sockets: set[Path] = set()

        self.profile: Optional[str] = None

        self.called_chroot = False
        self.protocols: set[Protocol] = set()
        self.wx_mem = False

    def run_program(self) -> None:
        """Run the program with strace."""
        with tempfile.NamedTemporaryFile() as tmpf:
            strace_cmd = [
                "strace",
                f"--trace=%file,socket,connect,{','.join(MDWE_SYSCALLS)}",
                "--quiet=all",
                "--signal=none",
                "--status=!unfinished",
                "--follow-forks",
                "--output",
                tmpf.name,
            ]
            subprocess.run(
                [
                    *shlex.split(self.firejail_cmd),
                    *strace_cmd,
                    "--",
                    self.program,
                    *self.arguments,
                ],
                check=True,
            )
            self.strace_output = tmpf.read().decode()
            # import shutil
            # shutil.copy(tmpf.name, ".")

    def handle_socket_syscall(self, syscall: str, args: str) -> None:
        """Handle socket syscall"""
        if "AF_UNIX" in args:
            self.protocols.add(Protocol.AF_UNIX)
        elif "AF_INET6" in args:
            self.protocols.add(Protocol.AF_INET6)
        elif "AF_INET" in args:
            self.protocols.add(Protocol.AF_INET)
        elif "AF_NETLINK" in args:
            self.protocols.add(Protocol.AF_NETLINK)

    def handle_connect_syscall(self, syscall: str, args: str) -> None:
        """Handle connect syscall"""
        sockaddr = re.match(
            r'{sa_family=(?P<sa_family>[A-Z0-9_]+), sun_path="(?P<sun_path>.+)"}', args
        )
        if sockaddr:
            sa_family = sockaddr["sa_family"]
            sun_path = sockaddr["sun_family"]
            if sa_family == "AF_UNIX":
                self.sockets.add(Path(sun_path))

    def handle_mdwe_syscalls(self, syscall: str, args: str) -> None:
        """Handle mdwe syscalls"""
        if self.wx_mem:
            return

        if syscall in ("mmap", "mmap2"):
            self.wx_mem = "PROT_WRITE|PROT_EXEC" in args
        elif syscall in ("mprotect", "pkey_mprotect"):
            self.wx_mem = "PROT_EXEC" in args
        elif syscall == "memfd_create":
            self.wx_mem = True
        elif syscall == "shmat":
            self.wx_mem = "SHM_EXEC" in args

    def handle_fs_syscalls(self, syscall: str, args: str) -> None:
        """Handle %file syscalls"""
        SYSCALL_ARGN_ACCESSKIND = {
            # "access": (0, AccessKind.STAT),
            "chdir": (0, AccessKind.OPEN),
            "chroot": (0, AccessKind.OPEN),
            "execve": (0, AccessKind.EXEC),
            # "faccessat2": (1, AccessKind.STAT),
            "mkdir": (0, AccessKind.CREAT),
            # "newfstatat": (1, AccessKind.STAT),
            "open": (0, AccessKind.OPEN),
            "openat": (1, AccessKind.OPEN),
            # "readlink": (0, AccessKind.STAT),
            # "stat": (0, AccessKind.STAT),
            # "statfs": (0, AccessKind.STAT),
            # "statx": (1, AccessKind.STAT),
        }

        get_path: Callable[[str, int], str] = lambda args, n: (
            os.path.normpath(args.split(",")[n].strip(' "'))
        )

        if syscall == "chroot":
            self.called_chroot = True

        try:
            arg_n, access_kind = SYSCALL_ARGN_ACCESSKIND[syscall]
        except KeyError:
            if syscall in (
                "newfstatat",
                "access",
                "faccessat2",
                "access",
                "readlink",
                "stat",
                "statfs",
                "statx",
            ):
                return
            print(
                f"firejail-profile-builder.py: Not Implemented: {syscall=}",
                file=sys.stderr,
            )
            return
        self.paths[Path(get_path(args, arg_n))].add(access_kind)

    def parse_strace_output(self) -> None:
        """Parses strace output."""
        assert self.strace_output is not None
        for line in self.strace_output.splitlines():
            parsed_line = re.match(r"\d+\s+(?P<syscall>\w+)\((?P<args>.*)\)", line)
            if not parsed_line:
                print(f"firejail-profile-builder.py: Skipping strace_output {line=}")
                continue
            syscall = parsed_line["syscall"]
            args = parsed_line["args"]

            if syscall == "socket":
                self.handle_socket_syscall(syscall, args)
            elif syscall == "connect":
                self.handle_connect_syscall(syscall, args)
            elif syscall in MDWE_SYSCALLS:
                self.handle_mdwe_syscalls(syscall, args)
            else:
                self.handle_fs_syscalls(syscall, args)

    def build(self) -> str:
        """Returns the profile for self.program and builds it if necessary."""
        if self.profile:
            return self.profile

        self.run_program()
        self.parse_strace_output()

        self.profile = f"""# Firejail profile for {self.program} (generated by firejail-profile-builder.py)
        #quiet
        # Persistent local customizations
        #include <FIXME>.local
        # Persistent global definitions
        include globals.local

        {self.build_ignore_noexec_home()}
        {self.build_ignore_noexec_tmp()}

        {self.build_noblacklist()}

        {self.build_allow_bin_sh()}

        # Allows files commonly used by IDEs
        #include allow-common-devel.inc

        # Allow gjs (blacklisted by disable-interpreters.inc)
        #include allow-gjs.inc

        # Allow java (blacklisted by disable-devel.inc)
        #include allow-java.inc

        # Allow lua (blacklisted by disable-interpreters.inc)
        #include allow-lua.inc

        # Allow perl (blacklisted by disable-interpreters.inc)
        #include allow-perl.inc

        {self.build_allow_python()}

        # Allow ruby (blacklisted by disable-interpreters.inc)
        #include allow-ruby.inc

        # Allow ssh (blacklisted by disable-common.inc)
        #include allow-ssh.inc

        # Disable Wayland
        #blacklist ${{RUNUSER}}/wayland-*
        #blacklist ${{RUNUSER}}
        {self.build_blacklist_libexec()}

        include disable-common.inc
        include disable-devel.inc
        include disable-exec.inc
        include disable-interpreters.inc
        include disable-proc.inc
        include disable-programs.inc
        #include disable-shell.inc
        #include disable-X11.inc
        #include disable-xdg.inc

        #mkdir PATH
        #mkfile PATH
        {self.build_whitelist()}
        include whitelist-common.inc
        include whitelist-run-common.inc
        include whitelist-runuser-common.inc
        include whitelist-usr-share-common.inc
        include whitelist-var-common.inc

        caps.drop all
        #ipc-namespace
        {self.build_machine_id()}
        {self.build_net_none()}
        netfilter
        no3d
        nodvd
        nogroups
        noinput
        nonewprivs
        {self.build_noprinters()}
        noroot
        {self.build_nosound()}
        notv
        nou2f
        {self.build_novideo()}
        protocol {self.build_protocol()}
        {self.build_seccomp()}
        seccomp.block-secondary
        shell none
        tracelog
        ##x11 none

        {self.build_disable_mnt()}
        private-bin {self.build_private_bin()}
        private-cache
        private-dev
        private-etc {self.build_private_etc()}
        private-tmp

        #dbus-user none
        dbus-system none

        {self.build_memory_deny_write_execute()}
        #read-only ${{HOME}}
        """.replace(
            "\n        ", "\n"
        )

        return self.profile

    def build_ignore_noexec_home(self) -> str:
        """Returns 'ignore noexec ${HOME}' if needed"""
        if any(
            AccessKind.EXEC in access_kinds
            for path, access_kinds in self.paths.items()
            if HOME in path.parents
        ):
            return "ignore noexec ${HOME}"
        return "# Uncomment to allow executing programs in ${HOME}.\n#ignore noexec ${HOME}"

    def build_ignore_noexec_tmp(self) -> str:
        """Returns 'ignore noexec /tmp' if needed"""
        if any(
            AccessKind.EXEC in access_kinds
            for path, access_kinds in self.paths.items()
            # if os.path.commonpath(["/tmp", path]) == "/tmp"
            if Path("/tmp") in path.parents
        ):
            return "ignore noexec /tmp"
        return "# Uncomment to allow executing programs in /tmp.\n#ignore noexec /tmp"

    def build_noblacklist(self) -> str:
        """Returnsthe noblacklist"""
        noblacklist = set()
        for path in self.paths:
            if path in DISABLE_COMMON or path in DISABLE_PROGRAMS:
                spath = (
                    str(path)
                    .replace(str(HOME), "${HOME}")
                    .replace(str(RUNUSER), "${RUNUSER}")
                )
                noblacklist.add(f"noblacklist {spath}")
            for parent in path.parents:
                if parent in DISABLE_COMMON or parent in DISABLE_PROGRAMS:
                    sparent = (
                        str(parent)
                        .replace(str(HOME), "${HOME}")
                        .replace(str(RUNUSER), "${RUNUSER}")
                    )
                    noblacklist.add(f"noblacklist {sparent}")
        return "\n".join(sorted(noblacklist))

    def build_allow_bin_sh(self) -> str:
        """Retruns allow-bin-sh.inc if needed"""
        bin_shs = [
            "/bin/sh",
            "/usr/bin/sh",
            "/bin/bash",
            "/usr/bin/bash",
            "/bin/dash",
            "/usr/bin/dash",
        ]
        if any(Path(bin_sh) in self.paths for bin_sh in bin_shs):
            return (
                "# Allow /bin/sh (blacklisted by disable-shell.inc)\n"
                "include allow-bin-sh.inc"
            )
        return (
            "# Allow /bin/sh (blacklisted by disable-shell.inc)\n"
            "#include allow-bin-sh.inc"
        )

    def build_allow_python(self) -> str:
        """Returns allow-python?.inc if needed"""
        # TODO: Allow python2 only if necessary
        if any(
            path.parent == Path("/usr/bin")
            and path.name.startswith("python")
            and AccessKind.EXEC in access_kinds
            for path, access_kinds in self.paths.items()
        ):
            return (
                "# Allow python (blacklisted by disable-interpreters.inc)\n"
                "include allow-python2.inc\n"
                "include allow-python3.inc"
            )
        return (
            "# Allow python (blacklisted by disable-interpreters.inc)\n"
            "#include allow-python2.inc\n"
            "#include allow-python3.inc"
        )

    def build_blacklist_libexec(self) -> str:
        """Returns 'blacklist /usr/libexec' if possible"""
        if any(Path("/usr/libexec") in path.parents for path in self.paths):
            return ""
        return "blacklist /usr/libexec"

    def build_whitelist(self) -> str:
        """Returns the whitelist"""
        whitelist = []
        for path, access_kind in self.paths.items():
            if AccessKind.OPEN not in access_kind:
                continue
            if "flatpak/exports" in str(path) or "firecfg.py/overrides" in str(path):
                continue
            if HOME in path.parents:
                if not WHITELIST_COMMON.affects(path):
                    spath = str(path).replace(str(HOME), "${HOME}")
                    whitelist.append(f"whitelist {spath}")
            elif RUNUSER in path.parents:
                if not WHITELIST_RUNUSER_COMMON.affects(path):
                    spath = str(path).replace(str(RUNUSER), "${RUNUSER}")
                    whitelist.append(f"whitelist {spath}")
            elif Path("/run") in path.parents:
                if not WHITELIST_RUN_COMMON.affects(path):
                    whitelist.append(f"whitelist {path}")
            elif Path("/usr/share") in path.parents:
                if not WHITELIST_USR_SHARE_COMMON.affects(path):
                    whitelist.append(f"whitelist {path}")
            elif Path("/var") in path.parents:
                if not WHITELIST_VAR_COMMON.affects(path):
                    whitelist.append(f"whitelist {path}")
        whitelist.sort()
        return "\n".join(whitelist)

    def build_machine_id(self) -> str:
        """Returns machine-id if possible"""
        if RUNUSER / "pulse/native" in self.sockets:
            return "#machine-id"
        return "machine-id"

    def build_net_none(self) -> str:
        """Returns net none if possible"""
        if Protocol.AF_INET in self.protocols:
            return "# Uncomment to disable network access.\n#net none"
        return "net none"

    def build_noprinters(self) -> str:
        """Returns noprinters if possible"""
        if Path("/run/cups/cups.sock") in self.sockets:
            return "#noprinters"
        return "noprinters"

    def build_nosound(self) -> str:
        """Returns nosound if possible"""
        if RUNUSER / "pulse/native" in self.sockets:
            return "# Uncomment to disable audio output/input.#nosound"
        return "nosound"

    def build_novideo(self) -> str:
        """Returns 'novideo' if possible"""
        if any(str(path).startswith("/dev/video") for path in self.paths):
            return "# Uncomment to disable video devices.\n#novideo"
        return "novideo"

    def build_protocol(self) -> str:
        """Returns all used protocols"""
        protocol = ""
        if Protocol.AF_UNIX in self.protocols:
            protocol += "unix,"
        if Protocol.AF_INET in self.protocols:
            protocol += "inet,"
        if Protocol.AF_INET6 in self.protocols:
            protocol += "inet6,"
        if Protocol.AF_NETLINK in self.protocols:
            protocol += "netlink,"
        return protocol[:-1]

    def build_seccomp(self) -> str:
        """Returns seccomp with added/removed syscalls"""
        syscall_list = []
        if self.called_chroot:
            syscall_list.append("!chroot")
        if len(self.protocols) == 0:
            syscall_list.append("socket")
        return f"seccomp {','.join(syscall_list)}" if syscall_list else "seccomp"

    def build_disable_mnt(self) -> str:
        """Returns 'disable-mnt' if possible"""
        is_mnt: Callable[[Path], bool] = lambda path: any(
            Path(mnt_prefix) in path.parents
            for mnt_prefix in ["/mnt", "/run/mnt", "/media", "/run/media"]
        )
        if any(is_mnt(path) for path in self.paths):
            return "disable-mnt"
        return (
            "# Uncomment to blacklist /mnt, /run/mnt, /media, /run/media.\n#disable-mnt"
        )

    def build_private_bin(self) -> str:
        """Returns all files accessed in {/usr,}/{s,}bin"""
        is_bindir: Callable[[Path], bool] = lambda path: any(
            Path(bin_prefix) in path.parents
            for bin_prefix in ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        )
        fixup_python: Callable[[str], str] = lambda name: (
            "python*" if name.startswith("python") else name
        )
        private_bin = [
            fixup_python(os.path.basename(path))
            for path, access_kinds in self.paths.items()
            if is_bindir(path) and AccessKind.EXEC in access_kinds
        ]
        private_bin.sort()
        return ",".join(private_bin)

    def build_private_etc(self) -> str:
        """Returns all files accessed in /etc"""
        files = {
            str(path)[len("/etc/") :]
            for path in self.paths.keys()
            if Path("/etc") in path.parents and "firecfg.py/overrides" not in str(path)
        }
        templates = [
            template
            for template in PRIVATE_ETC_TEMPLATES.values()
            if any(file.startswith(t_file) for t_file in template for file in files)
        ]
        for template in templates:
            files.update(template)
        return ",".join(
            sorted(
                (
                    file
                    for file in files
                    if all(not file.startswith(f) for f in files if f != file)
                ),
                key=str.casefold,
            )
        )

    def build_memory_deny_write_execute(self) -> str:
        """Returns memory-deny-write-execute if possible"""
        return "" if self.wx_mem else "memory-deny-write-execute"


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-o",
            "--output",
            required=True,
            help="Path where the profile should be written to",
        )
        parser.add_argument(
            "-f",
            "--force",
            action="store_true",
            help="Overwrite output file if it exists.",
        )
        parser.add_argument(
            "--firejail-cmd",
            default="firejail --quiet --noprofile --shell=none --private",
            help="[EXPERTS ONLY!]",
        )
        parser.add_argument("program")
        parser.add_argument("arguments", nargs=argparse.REMAINDER)
        args = parser.parse_args()

        profile = FirejailProfileBuilder(
            args.program, args.arguments, args.firejail_cmd
        ).build()
        if not args.force and os.path.exists(args.output):
            print(
                f"firejail-profile-build.py: '{args.output}' already exists, use -f to overwrite it.",
                file=sys.stderr,
            )
            sys.exit(2)
        with open(args.output, "w") as output:
            output.write(profile)
    except KeyboardInterrupt:
        pass
