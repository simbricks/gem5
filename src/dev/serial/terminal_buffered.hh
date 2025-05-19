/*
 * Copyright 2025 Max Planck Institute for Software Systems, and
 * National University of Singapore
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __DEV_TERMINAL_BUFFERED_HH__
#define __DEV_TERMINAL_BUFFERED_HH__

#include <iostream>
#include <set>

#include "base/callback.hh"
#include "base/circlebuf.hh"
#include "base/pollevent.hh"
#include "base/socket.hh"
#include "dev/serial/serial.hh"
#include "dev/serial/terminal.hh"
#include "params/TerminalBuffered.hh"
#include "sim/sim_object.hh"

namespace gem5
{

/**
 * Buffered terminal, that will only output complete lines of output, optionally
 * with a configured prefix. This is especially useful for simulations with
 * multiple terminals outputting to stdout/err to avoid char-wise interleaving,
 * and to be able to tell which output comes from which terminal.
 */
class TerminalBuffered : public Terminal
{
  protected:
    std::set<char> flush_chars;
    std::string prefix;
    std::string buffer;

    void flush();

  public:
    typedef TerminalBufferedParams Params;
    TerminalBuffered(const Params &p);
    ~TerminalBuffered();

  public: // SerialDevice interface
    void writeData(uint8_t c) override;
};

} // namespace gem5

#endif // __DEV_TERMINAL_BUFFERED_HH__
