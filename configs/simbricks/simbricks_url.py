# Copyright 2026 Max Planck Institute for Software Systems,
# National University of Singapore, and SimBricks UG (haftungsbeschränkt)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""Parsing of the SimBricks "URLs" the config scripts here take.

    ADDR[:ARGS]
    ADDR = connect:UX_SOCKET_PATH | listen:UX_SOCKET_PATH:SHM_PATH
    ARGS = sync | latency=XX | sync_interval=XX

The result is a dict of SimBricks adapter parameters, ready to be passed to
any of the SimBricks SimObjects.
"""

import sys


def malformed_url(s):
    print("Error: SimBricks URL", s, "is malformed")
    sys.exit(1)


def parse_simbricks_url(s):
    """Turn a SimBricks URL into adapter parameters."""
    out = {"sync": False}
    parts = s.split(":")
    if len(parts) < 2:
        malformed_url(s)

    if parts[0] == "connect":
        out["listen"] = False
        out["uxsocket_path"] = parts[1]
        parts = parts[2:]
    elif parts[0] == "listen":
        if len(parts) < 3:
            malformed_url(s)
        out["listen"] = True
        out["uxsocket_path"] = parts[1]
        out["shm_path"] = parts[2]
        parts = parts[3:]
    else:
        malformed_url(s)

    for p in parts:
        if p == "sync":
            out["sync"] = True
        elif p.startswith("sync_interval="):
            out["sync_tx_interval"] = p.split("=")[1]
        elif p.startswith("latency="):
            out["link_latency"] = p.split("=")[1]
        else:
            malformed_url(s)
    return out
