# Copyright 2026 SimBricks UG (haftungsbeschränkt)
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

from m5.objects.InstTracer import InstTracer
from m5.params import *
from m5.proxy import *


class SimBricksTracer(InstTracer):
    """Logs syscall/sysret/iret and kernel function hooks for simbricks-trace
    (debug flag SimBricksCpu). Attach as cpu.tracer on every CPU; the hook
    list is installed once per system."""

    type = "SimBricksTracer"
    cxx_class = "gem5::simbricks::Tracer"
    cxx_header = "simbricks/tracer.hh"

    system = Param.System(Parent.any, "system whose kernel symbols and "
                          "thread contexts the hooks use")
    hooks = VectorParam.String(
        [], "hooks: 'symbol[:reg,reg,...][:ret]' (symbol or 0x address)")
