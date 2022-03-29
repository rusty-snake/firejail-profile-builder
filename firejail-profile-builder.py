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
import os.path
import pathlib
import re
import subprocess
import sys
import tempfile


def get_cli_args(argv: list[str]) -> dict[str, str]:
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("program")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    return vars(parser.parse_args(argv[1:]))


def run_program(program: str, arguments: list[str]) -> list[str]:
    with tempfile.NamedTemporaryFile() as tmpf:
        subprocess.run(
            [
                "firejail",
                "--quiet",
                "--noprofile",
                "--private",
                "strace",
                "-e",
                "%file",
                "--quiet=all",
                "--follow-forks",
                "--output",
                tmpf.name,
                "--",
                program,
                *arguments,
            ],
            check=True,
        )
        return list(tmpf.read().decode().splitlines())


def parse_strace_output(strace_output: list[str]) -> dict[str, set[str]]:
    paths = {
        "open": set(),
        "stat": set(),
        "exec": set(),
    }
    for line in strace_output:
        parsed_line = re.match(
            r"\d+\s+(?P<syscall>\w+)\((?P<args>.*)\)", line
        ).groupdict()
        syscall = parsed_line["syscall"]
        args = parsed_line["args"].split(",")
        if syscall == "open":
            paths["open"].add(args[0].strip(' "'))
        elif syscall == "openat":
            paths["open"].add(args[1].strip(' "'))
        elif syscall == "access":
            paths["stat"].add(args[0].strip(' "'))
        elif syscall == "stat":
            paths["stat"].add(args[0].strip(' "'))
        elif syscall == "newfstatat":
            paths["stat"].add(args[1].strip(' "'))
        elif syscall == "execve":
            paths["exec"].add(args[0].strip(' "'))
        else:
            print(
                f"firejail-profile-builder.py: Not Implemented: {syscall=}",
                file=sys.stderr,
            )
    return paths


def build_profile(paths: dict[str, set[str]]) -> str:
    whitelist = []
    private_bin = []
    ignore_noexec_home = False
    for path in paths["open"]:
        if path.startswith(str(pathlib.Path.home())):
            whitelist.append(path.replace(str(pathlib.Path.home()), "${HOME}"))
        elif (
            path.startswith("/bin")
            or path.startswith("/sbin")
            or path.startswith("/usr/bin")
            or path.startswith("/usr/sbin")
        ):
            private_bin.append(os.path.basename(path))
    for path in paths["exec"]:
        if path.startswith(str(pathlib.Path.home())):
            ignore_noexec_home = True
        elif (
            path.startswith("/bin")
            or path.startswith("/sbin")
            or path.startswith("/usr/bin")
            or path.startswith("/usr/sbin")
        ):
            private_bin.append(os.path.basename(path))

    return f"""\
{"ignore noexec ${HOME}" if ignore_noexec_home else "# Uncomment to allow executing programs in ${HOME}.<br>#ignore noexec ${HOME}"}

include disable-common.inc
include disable-exec.inc
include disable-programs.inc

{"<br>".join(f"whitelist {path}" for path in whitelist)}
include whitelist-common.inc

private-bin {",".join(private_bin)}
""".replace(
        "<br>", "\n"
    )


def main(argv: list[str]) -> int:
    args = get_cli_args(argv)
    strace_output = run_program(args["program"], args["arguments"])
    paths = parse_strace_output(strace_output)
    with open(args["output"], "w") as output:
        output.write(build_profile(paths))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        pass
