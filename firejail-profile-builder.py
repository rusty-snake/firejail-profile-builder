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

import argparse
import enum
import os
import os.path
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from collections.abc import Iterator
from typing import Callable, Optional
from pathlib import Path


class BlacklistInc:
    def __init__(self, path: str):
        self.path = path
        self._blacklist: Optional[list[str]] = None

    @property
    def blacklist(self) -> list[str]:
        if not self._blacklist:
            with open(self.path) as raw_blacklist:
                self._blacklist = [
                    line[len("blacklist ") :].strip()
                    for line in raw_blacklist
                    if line.startswith("blacklist ")
                ]
        return self._blacklist

    def __iter__(self) -> Iterator[str]:
        return iter(self.blacklist)

    def __contains__(self, path: str) -> bool:
        return path in self.blacklist


class WhitelistInc:
    def __init__(self, path: str):
        self.path = path
        self._whitelist: Optional[list[str]] = None

    @property
    def whitelist(self) -> list[str]:
        if not self._whitelist:
            with open(self.path) as raw_whitelist:
                self._whitelist = [
                    line[len("whitelist ") :].strip()
                    for line in raw_whitelist
                    if line.startswith("whitelist ")
                ]
        return self._whitelist

    def __iter__(self) -> Iterator[str]:
        return iter(self.whitelist)

    def __contains__(self, path: str) -> bool:
        return path in self.whitelist


WHITELIST_COMMON = WhitelistInc("/etc/firejail/whitelist-common.inc")
WHITELIST_RUN_COMMON = WhitelistInc("/etc/firejail/whitelist-run-common.inc")
WHITELIST_RUNUSER_COMMON = WhitelistInc("/etc/firejail/whitelist-runuser-common.inc")
WHITELIST_USR_SHARE_COMMON = WhitelistInc(
    "/etc/firejail/whitelist-usr-share-common.inc"
)
WHITELIST_VAR_COMMON = WhitelistInc("/etc/firejail/whitelist-var-common.inc")

DISABLE_COMMON = BlacklistInc("/etc/firejail/disable-common.inc")
DISABLE_PROGRAMS = BlacklistInc("/etc/firejail/disable-programs.inc")

MDWE_SYSCALLS = (
    "mmap",
    "mmap2",
    "mprotect",
    "pkey_mprotect",
    "memfd_create",
    "shmat",
)

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


class AccessKind(enum.Enum):
    """Possible access kinds"""

    CREAT = enum.auto()
    EXEC = enum.auto()
    OPEN = enum.auto()
    STAT = enum.auto()


class FirejailProfileBuilder:
    def __init__(self, program: str, arguments: list[str]):
        self.program = program
        self.arguments = arguments

        self.strace_output: Optional[str] = None
        self.paths: defaultdict[
            Path, set[AccessKind]
        ] = defaultdict(set)

        self.profile: Optional[str] = None

        self.called_chroot = False
        self.printers = False
        self.protocols: set[Protocol] = set()
        self.wx_mem = False

    def run_program(self) -> None:
        """Run the program with strace."""
        with tempfile.NamedTemporaryFile() as tmpf:
            firejail_cmd = [
                "firejail",
                "--quiet",
                "--noprofile",
                "--shell=none",
                "--private",
            ]
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
                    *firejail_cmd,
                    *strace_cmd,
                    "--",
                    self.program,
                    *self.arguments,
                ],
                check=True,
            )
            self.strace_output = tmpf.read().decode()

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
        if '{sa_family=AF_UNIX, sun_path="/run/cups/cups.sock"}' in args:
            self.printers = True

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

        # Allow /bin/sh (blacklisted by disable-shell.inc)
        #include allow-bin-sh.inc

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
        #machine-id
        {self.build_net_none()}
        netfilter
        no3d
        nodvd
        nogroups
        noinput
        nonewprivs
        {self.build_noprinters()}
        noroot
        #nosound
        notv
        nou2f
        {self.build_novideo()}
        protocol {self.build_protocol()}
        {self.build_seccomp()}
        seccomp.block-secondary
        #seccomp.keep
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
            #if os.path.commonpath(["/tmp", path]) == "/tmp"
            if Path("/tmp") in path.parents
        ):
            return "ignore noexec /tmp"
        return "# Uncomment to allow executing programs in /tmp.\n#ignore noexec /tmp"

    def build_noblacklist(self) -> str:
        pass
        #for path in paths:
            #if (path or parents) in DISABLE_COMMON | DISABLE_PROGRAMS:
                #noblacklist {blacklist}

    def build_allow_python(self) -> str:
        """Returns allow-python?.inc if needed"""
        # TODO: Allow python2 only if necessary
        if any(
            # str(path).startswith("/usr/bin/python") and ...
            path.parent == Path("/usr/bin") and path.name.startswith("python") and AccessKind.EXEC in access_kinds
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
        for path in self.paths:
            if "flatpak/exports" in str(path):
                continue
            if HOME in path.parents:
                spath = str(path).replace(str(HOME), "${HOME}")
                if all(not spath.startswith(p) for p in WHITELIST_COMMON):
                    whitelist.append(f"whitelist {spath}")
            elif Path("/run") in path.parents:
                if all(p not in map(str, path.parents) for p in WHITELIST_RUN_COMMON):
                    whitelist.append(f"whitelist {path}")
            elif RUNUSER in path.parents:
                spath = str(path).replace(str(RUNUSER), "${RUNUSER}")
                if all(not spath.startswith(p) for p in WHITELIST_RUNUSER_COMMON):
                    whitelist.append(f"whitelist {spath}")
            elif Path("/usr/share") in path.parents:
                if all(p not in map(str, path.parents) for p in WHITELIST_USR_SHARE_COMMON):
                    whitelist.append(f"whitelist {path}")
            elif Path("/var") in path.parents:
                if all(p not in map(str, path.parents) for p in WHITELIST_VAR_COMMON):
                    whitelist.append(f"whitelist {path}")
        whitelist.sort()
        return "\n".join(whitelist)

    def build_net_none(self) -> str:
        """Returns net none if possible"""
        if Protocol.AF_INET in self.protocols:
            return "# Uncomment to disable network access.\n#net none"
        return "net none"

    def build_noprinters(self) -> str:
        return "#noprinters" if self.printers else "noprinters"

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
        return "seccomp !chroot" if self.called_chroot else "seccomp"

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
        # TODO: python3.8 -> python3*
        is_bindir: Callable[[Path], bool] = lambda path: any(
            Path(bin_prefix) in path.parents
            for bin_prefix in ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        )
        return ",".join(
            os.path.basename(path)
            for path, access_kinds in self.paths.items()
            if is_bindir(path) and AccessKind.EXEC in access_kinds
        )

    def build_private_etc(self) -> str:
        """Returns all files accessed in /etc"""
        # TODO: Templates
        files = [
            str(path)[len("/etc/") :]
            for path in self.paths.keys()
            if Path("/etc") in path.parents
        ]
        cleaned_files = sorted(
            file
            for file in files
            if all(not file.startswith(f) for f in files if f != file)
        )
        return ",".join(cleaned_files)

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
        # parser.add_argument("--firejail-cmd")
        parser.add_argument("program")
        parser.add_argument("arguments", nargs=argparse.REMAINDER)
        args = parser.parse_args()

        profile = FirejailProfileBuilder(args.program, args.arguments).build()
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
