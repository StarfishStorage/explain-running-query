#!/usr/bin/env python3
# Any Python 3 interpreter should suffice to run this script as it can be run in production environment.

# MIT License
#
# Copyright 2020 Starfish Storage Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE

import errno
import re
import subprocess
import sys
import logging
from argparse import ArgumentParser
from contextlib import contextmanager


def get_backtrace(gdb):
    main_func_regexp = re.compile("#[0-9]+ +0x[0-9a-f]+ in main ")

    backtrace = []
    gdb.cmd("backtrace")
    line = gdb.stdout.readline()
    while line:
        if "No stack." in line:
            return []
        backtrace.append(line)
        if main_func_regexp.search(line):
            # one more read and the process gets blocked
            break
        line = gdb.stdout.readline()

    return backtrace


def get_depth_of_exec_function(backtrace):
    """
    >>> get_depth_of_exec_function(["#1  0x00007f29e6eb7df5 in standard_ExecutorRun (queryDesc=0x562aad346d38,"])
    1
    >>> get_depth_of_exec_function(["#27 0x00007f29e6eb7df5 in pgss_ExecutorRun (queryDesc=0x562aad346d38,"])
    27
    >>> get_depth_of_exec_function(["#13 0x00007f29e6eb7df5 in explain_ExecutorRun (queryDesc=0x562aad346d38,"])
    13
    >>> get_depth_of_exec_function(["#4  0x00007f29e6eb7df5 in ExecEvalNot (notclause=<optimized out>,"])
    4
    >>> get_depth_of_exec_function(["#5  0x00007f29e6eb7df5 in ExecProcNode (node=node@entry=0x562aad157358,)"])
    5
    >>> get_depth_of_exec_function(["#12 0x00007f29e6eb7df5 in ExecutePlan (dest=0x562aad15e290,"])
    12
    >>> get_depth_of_exec_function(["#21 standard_ExecutorRun (queryDesc=0x562aad0b46f8, direction=<optimized out>,"])
    21
    >>> bt = ["#0  palloc0 (size=size@entry=328)", \
              "#1  0x0000562aac6c9970 in InstrAlloc (n=n@entry=1, instrument_options=4)", \
              "#2  0x0000562aac6bdddb in ExecInitNode (node=node@entry=0x562aad49e818,"]
    >>> get_depth_of_exec_function(bt)
    2
    """
    exec_regexp = re.compile(r"#([0-9]+) .*Exec[a-zA-Z]+ \(")
    for frame in backtrace:
        m = exec_regexp.search(frame)
        if m:
            return int(m.group(1))
    return None


def run_until_returns_from_depth_functions(gdb, depth):
    for _ in range(depth):
        gdb.cmd("finish")


def get_query_desc_ptr(backtrace):
    """
    >>> get_query_desc_ptr(["#21 standard_ExecutorRun (queryDesc=0x562aad0b46f8, direction=<optimized out>,"])
    '0x562aad0b46f8'
    >>> get_query_desc_ptr(["#1  pgss_ExecutorRun (queryDesc=0x562aad0b46f8, direction=<optimized out>,"])
    '0x562aad0b46f8'
    """
    query_desc_ptr_regexp = re.compile(r"ExecutorRun \(queryDesc=(0x[0-9a-f]+)[,\)]")
    # ExecutorRun can appear more than once in backtrace when running PL/pgSQL code. Return the deepest one.
    for frame in backtrace:
        m = query_desc_ptr_regexp.search(frame)
        if m:
            return m.group(1)
    return None


def create_explain_state_ptr(gdb):
    explain_state_ptr_regexp = re.compile(r"\(ExplainState \*\) (0x[0-9a-f]+)")

    gdb.cmd("call NewExplainState()")
    line = gdb.stdout.readline()
    while line:
        m = explain_state_ptr_regexp.search(line)
        if m:
            return m.group(1)
        line = gdb.stdout.readline()


class NotSupportedGdbVersion(Exception):
    pass


class Gdb(subprocess.Popen):
    GDB_PATH = "gdb"

    @staticmethod
    def get_gdb_version():
        """ Example outputs of gdb --version:
                GNU gdb (GDB) Red Hat Enterprise Linux (7.2-92.el6)
                GNU gdb (GDB) Red Hat Enterprise Linux 7.6.1-115.el7
                GNU gdb (Ubuntu 8.1-0ubuntu3.1) 8.1.0.20180409-git
                GNU gdb (Ubuntu 8.2-0ubuntu1~18.04) 8.2
        """
        version_regexp = re.compile(r"([0-9]+)\.([0-9]+)[^0-9]")
        gdb = subprocess.Popen([Gdb.GDB_PATH, '--version'], stdout=subprocess.PIPE, universal_newlines=True)
        stdout, _stderr = gdb.communicate()
        first_line = stdout.splitlines()[0]
        m = version_regexp.search(first_line)
        if m:
            major = int(m.group(1))
            minor = int(m.group(2))
            return major, minor
        logging.warning("Couldn't detect gdb version from: \"%s\", assuming it's at least 7.4", first_line)
        return 7, 4  # if it's older the script will fail anyway

    def __init__(self, pid):
        major, minor = self.get_gdb_version()
        if (major, minor) < (7, 4):
            raise NotSupportedGdbVersion(
                "gdb < 7.4 is not supported, because it fails with \"Hangup detected on fd 0\" "
                "when stdin is redirected to a pipe.\n"
                "See https://sourceware.org/bugzilla/show_bug.cgi?id=8677 for more details."
            )
        super().__init__(
            [Gdb.GDB_PATH, '--silent', '--pid', str(pid)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )

    def cmd(self, command):
        self.stdin.write(command + "\n")
        self.stdin.flush()


@contextmanager
def gdb_session(pid):
    try:
        gdb = Gdb(pid)
    except EnvironmentError as exc:
        if exc.errno == errno.ENOENT:
            logging.error("gdb not found")
            sys.exit(1)
    except NotSupportedGdbVersion as exc:
        logging.error(exc)
        sys.exit(1)

    try:
        yield gdb
    except KeyboardInterrupt:
        logging.error("Interrupted by user")
    finally:
        if gdb.poll() is None:
            logging.warning("Terminating gdb process (PID: {pid})".format(pid=gdb.pid))
            gdb.terminate()
            stdout, stderr = gdb.communicate(None, timeout=15)
        if gdb.poll() != 0:
            logging.error(
                "gdb process (PID: {pid}) exited with {code}\nSTDOUT: {out}\nSTDERR: {err}".format(
                    pid=gdb.pid, code=gdb.poll(), out=stdout, err=stderr
                )
            )
            sys.exit(1)


def main():
    logging.basicConfig(stream=sys.stderr, format="%(levelname)s: %(message)s", level=logging.INFO)
    parser = ArgumentParser(
        description="Print the plan of a running PostgreSQL query. "
        "gdb >= 7.4 and postgresql debuginfo package need to be installed."
    )
    parser.add_argument('pid', type=int, help="PID of PostgreSQL backend process that is running a query")
    args = parser.parse_args()
    with gdb_session(args.pid) as gdb:
        gdb.cmd("set prompt")
        gdb.cmd("set pagination off")  # traceback can be long
        gdb.cmd("set width unlimited")  # each stack frame in a single line
        gdb.cmd("set confirm off")  # no confirmation logs on quit
        backtrace = get_backtrace(gdb)
        if not backtrace:
            logging.error(
                "No stack found. Is the process running and you have permissions to run gdb on it? "
                "Try running this script as root."
            )
            sys.exit(1)
        query_desc_ptr = get_query_desc_ptr(backtrace)
        if not query_desc_ptr:
            logging.error(
                """It seems that process {pid} is not executing a query plan.
Possible reasons:
- postgresql debuginfo package is not installed
- query is finishing
- query has just started and the plan is not ready yet.""".format(
                    pid=args.pid
                )
            )
            sys.exit(1)

        exec_depth = get_depth_of_exec_function(backtrace)
        assert exec_depth is not None, "Found queryDesc in ExecutorRun but no Exec function, backtrace:\n{bt}".format(
            bt="".join(backtrace)
        )

        # PostgreSQL may be in the middle of a low-level function. Calling functions to explain query may break its
        # internal state and cause a segfault.
        logging.info("Waiting for low-level functions to finish. This may take a while." "")
        run_until_returns_from_depth_functions(gdb, exec_depth)

        explain_state_ptr = create_explain_state_ptr(gdb)
        # based on https://github.com/postgres/postgres/blob/bd29bc417e7130/contrib/auto_explain/auto_explain.c#L331
        gdb.cmd("call ExplainBeginOutput({es_ptr})".format(es_ptr=explain_state_ptr))
        gdb.cmd("call ExplainQueryText({es_ptr}, {qd_ptr})".format(es_ptr=explain_state_ptr, qd_ptr=query_desc_ptr))
        gdb.cmd("call ExplainPropertyText(\"Plan\", \"\", {es_ptr})".format(es_ptr=explain_state_ptr))
        gdb.cmd("call ExplainPrintPlan({es_ptr}, {qd_ptr})".format(es_ptr=explain_state_ptr, qd_ptr=query_desc_ptr))
        gdb.cmd("call ExplainEndOutput({es_ptr})".format(es_ptr=explain_state_ptr))
        gdb.cmd("printf \"%s\", (*((ExplainState *){es_ptr})->str)->data".format(es_ptr=explain_state_ptr))
        stdout, stderr = gdb.communicate("quit", timeout=3)
        print(stdout, end='')
        if stderr:
            logging.error(stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
