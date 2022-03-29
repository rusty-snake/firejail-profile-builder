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
import collections
import enum
import os
import os.path
import pathlib
import re
import subprocess
import sys
import tempfile
import typing


class AccessKind(enum.Enum):
    """Possible access kinds"""

    EXEC = enum.auto()
    OPEN = enum.auto()
    STAT = enum.auto()


class FirejailProfileBuilder:
    def __init__(self, program: str, arguments: list[str]):
        self.program = program
        self.arguments = arguments
        self.home = str(pathlib.Path.home())
        self.runuser = f"/run/user/{os.getuid()}"
        self.profile: typing.Optional[str] = None
        self.strace_output: typing.Optional[str] = None
        self.paths: collections.defaultdict[
            str, set[AccessKind]
        ] = collections.defaultdict(set)
        with open("/etc/firejail/whitelist-common.inc") as wc:
            self.whitelist_common = [
                line[len("whitelist ") :].strip()
                for line in wc
                if line.startswith("whitelist ")
            ]
        with open("/etc/firejail/whitelist-run-common.inc") as wrc:
            self.whitelist_run_common = [
                line[len("whitelist ") :].strip()
                for line in wrc
                if line.startswith("whitelist ")
            ]
        with open("/etc/firejail/whitelist-runuser-common.inc") as wruc:
            self.whitelist_runuser_common = [
                line[len("whitelist ") :].strip()
                for line in wruc
                if line.startswith("whitelist ")
            ]
        with open("/etc/firejail/whitelist-usr-share-common.inc") as wusc:
            self.whitelist_usr_share_common = [
                line[len("whitelist ") :].strip()
                for line in wusc
                if line.startswith("whitelist ")
            ]
        with open("/etc/firejail/whitelist-var-common.inc") as wvc:
            self.whitelist_var_common = [
                line[len("whitelist ") :].strip()
                for line in wvc
                if line.startswith("whitelist ")
            ]

    def run_program(self) -> None:
        """Run the program with strace."""
        with tempfile.NamedTemporaryFile() as tmpf:
            subprocess.run(
                [
                    "firejail",
                    "--quiet",
                    "--noprofile",
                    "--shell=none",
                    "--private",
                    "strace",
                    "-e",
                    "%file",
                    "--quiet=all",
                    "--follow-forks",
                    "--output",
                    tmpf.name,
                    "--",
                    self.program,
                    *self.arguments,
                ],
                check=True,
            )
            self.strace_output = tmpf.read().decode()

    @staticmethod
    def get_arg(args: str, n: int) -> str:
        """Extracts the nth argument from args."""
        return args.split(",")[n].strip(' "')

    def parse_strace_output(self) -> None:
        """Parses strace output."""
        SYSCALL_ARGN_ACCESSKIND = {
            "open": (0, AccessKind.OPEN),
            "openat": (1, AccessKind.OPEN),
            "access": (0, AccessKind.STAT),
            "stat": (0, AccessKind.STAT),
            "statfs": (0, AccessKind.STAT),
            "statx": (1, AccessKind.STAT),
            "newfstatat": (1, AccessKind.STAT),
            "execve": (0, AccessKind.EXEC),
        }
        assert self.strace_output is not None
        for line in self.strace_output.splitlines():
            parsed_line = re.match(r"\d+\s+(?P<syscall>\w+)\((?P<args>.*)\)", line)
            if not parsed_line:
                raise NotImplementedError
            syscall = parsed_line["syscall"]
            try:
                arg_n, access_kind = SYSCALL_ARGN_ACCESSKIND[syscall]
            except KeyError:
                print(
                    f"firejail-profile-builder.py: Not Implemented: {syscall=}",
                    file=sys.stderr,
                )
                continue
            self.paths[self.get_arg(parsed_line["args"], arg_n)].add(access_kind)

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

        #noblacklist PATH

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
        #net none
        netfilter
        no3d
        nodvd
        nogroups
        noinput
        nonewprivs
        noprinters
        noroot
        #nosound
        notv
        nou2f
        {self.build_novideo()}
        protocol unix,inet,inet6,netlink
        seccomp
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

        #memory-deny-write-execute
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
            if path.startswith(self.home)
        ):
            return "ignore noexec ${HOME}"
        return "# Uncomment to allow executing programs in ${HOME}.\n#ignore noexec ${HOME}"

    def build_ignore_noexec_tmp(self) -> str:
        """Returns 'ignore noexec /tmp' if needed"""
        if any(
            AccessKind.EXEC in access_kinds
            for path, access_kinds in self.paths.items()
            if path.startswith("/tmp")
        ):
            return "ignore noexec /tmp"
        return "# Uncomment to allow executing programs in /tmp.\n#ignore noexec /tmp"

    def build_allow_python(self) -> str:
        """Returns allow-python?.inc if needed"""
        # TODO: Allow python2 only if necessary
        if any(
            path.startswith("/usr/bin/python") and AccessKind.EXEC in access_kinds
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
        if any(path.startswith("/usr/libexec") for path in self.paths):
            return ""
        return "blacklist /usr/libexec"

    def build_whitelist(self) -> str:
        """Returns the whitelist"""
        whitelist = []
        for path in self.paths:
            if path.startswith(self.home):
                path = path.replace("${HOME}", self.home)
                if all(not path.startswith(p) for p in self.whitelist_common):
                    whitelist.append(f"whitelist {path}")
            elif path.startswith("/run"):
                if all(not path.startswith(p) for p in self.whitelist_run_common):
                    whitelist.append(f"whitelist {path}")
            elif path.startswith(self.runuser):
                path = path.replace("${RUNUSER}", self.runuser)
                if all(not path.startswith(p) for p in self.whitelist_runuser_common):
                    whitelist.append(f"whitelist {path}")
            elif path.startswith("/usr/share"):
                if all(not path.startswith(p) for p in self.whitelist_usr_share_common):
                    whitelist.append(f"whitelist {path}")
            elif path.startswith("/var"):
                if all(not path.startswith(p) for p in self.whitelist_var_common):
                    whitelist.append(f"whitelist {path}")
        whitelist.sort()
        return "\n".join(whitelist)

    def build_novideo(self) -> str:
        """Returns 'novideo' if possible"""
        if any(path.startswith("/dev/video") for path in self.paths):
            return "# Uncomment to disable video devices.\n#novideo"
        return "novideo"

    def build_disable_mnt(self) -> str:
        """Returns 'disable-mnt' if possible"""
        is_mnt: typing.Callable[[str], bool] = lambda path: any(
            path.startswith(mnt_prefix)
            for mnt_prefix in ["/mnt", "/run/mnt", "/media", "/run/media"]
        )
        if any(is_mnt(path) for path in self.paths):
            return "disable-mnt"
        return "#disable-mnt"

    def build_private_bin(self) -> str:
        """Returns all files accessed in {/usr,}/{s,}bin"""
        # TODO: python3.8 -> python3*
        is_bindir: typing.Callable[[str], bool] = lambda path: any(
            path.startswith(bin_prefix)
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
        return ",".join(
            os.path.basename(path)
            for path in self.paths.keys()
            if path.startswith("/etc")
        )


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
