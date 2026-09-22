/*
 * Copyright (c) 2026 The Regents of the University of California
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @file
 * Tests for the read-only qcow2 reader.
 *
 * Fixtures are built with qemu-img/qemu-io, and the expected content is
 * whatever 'qemu-img convert -O raw' produces for the same chain. The reader
 * is therefore checked against qemu's own interpretation of the format
 * rather than against our understanding of it. Tests skip when the qemu
 * tools are not installed.
 */

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "base/cprintf.hh"
#include "config/have_libzstd.hh"
#include "dev/storage/qcow2_image.hh"

using namespace gem5;

namespace
{

constexpr uint64_t SECTOR = Qcow2Image::SectorBytes;
constexpr uint64_t MiB = 1024 * 1024;

bool
haveQemuTools()
{
    static const bool have =
        std::system("qemu-img --version >/dev/null 2>&1") == 0 &&
        std::system("qemu-io --version >/dev/null 2>&1") == 0;
    return have;
}

/** True if qemu-img can produce images using the given compression type. */
bool
haveCompression(const std::string &type)
{
    std::string cmd = csprintf(
        "qemu-img create -f qcow2 -o compression_type=%s "
        "/tmp/gem5-qcow2-probe.qcow2 1M >/dev/null 2>&1", type);
    bool ok = std::system(cmd.c_str()) == 0;
    std::error_code ec;
    std::filesystem::remove("/tmp/gem5-qcow2-probe.qcow2", ec);
    return ok;
}

class Qcow2ImageTest : public ::testing::Test
{
  protected:
    void
    SetUp() override
    {
        if (!haveQemuTools())
            GTEST_SKIP() << "qemu-img/qemu-io not available";

        char tmpl[] = "/tmp/gem5-qcow2-XXXXXX";
        ASSERT_NE(mkdtemp(tmpl), nullptr);
        dir = tmpl;
    }

    void
    TearDown() override
    {
        if (dir.empty())
            return;
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    std::string p(const std::string &n) const { return dir + "/" + n; }

    /** Run a shell command in the fixture directory. */
    void
    sh(const std::string &cmd)
    {
        std::string full =
            csprintf("cd %s && %s >/dev/null 2>&1", dir, cmd);
        ASSERT_EQ(std::system(full.c_str()), 0) << "failed: " << cmd;
    }

    /**
     * Read every sector of `image` through Qcow2Image and compare it against
     * qemu's own rendering of the same chain.
     */
    void
    expectMatchesQemu(const std::string &image,
                      const std::vector<std::string> &searchPath = {})
    {
        sh(csprintf("qemu-img convert -f qcow2 -O raw %s truth.raw", image));

        std::ifstream truth(p("truth.raw"), std::ios::binary);
        ASSERT_TRUE(truth.good());

        Qcow2Image img("test", p(image), searchPath, 1 << 20, 16);
        img.open();

        std::ifstream::pos_type truthSize =
            std::filesystem::file_size(p("truth.raw"));
        ASSERT_EQ(img.size(), (uint64_t)truthSize)
            << "virtual size disagrees with qemu";

        uint64_t sectors = img.size() / SECTOR;
        std::vector<uint8_t> got(SECTOR), want(SECTOR);
        uint64_t mismatches = 0;

        for (uint64_t s = 0; s < sectors; s++) {
            img.readSector(s * SECTOR, got.data());
            truth.read((char *)want.data(), SECTOR);
            if (got != want && ++mismatches <= 5) {
                ADD_FAILURE()
                    << "sector " << s << " (byte " << s * SECTOR
                    << ") differs from qemu; first byte got 0x" << std::hex
                    << (int)got[0] << " want 0x" << (int)want[0];
            }
        }
        EXPECT_EQ(mismatches, 0u)
            << mismatches << " of " << sectors << " sectors differ from qemu";
    }

    /** Fill an image with a per-cluster pattern via a raw source. */
    void
    makePatternedBase(const std::string &name, const std::string &extraOpts = "")
    {
        std::ofstream os(p("pattern.raw"), std::ios::binary);
        std::vector<uint8_t> cluster(64 * 1024);
        for (int c = 0; c < 64; c++) {
            std::fill(cluster.begin(), cluster.end(), (uint8_t)(c * 7 + 1));
            os.write((const char *)cluster.data(), cluster.size());
        }
        os.close();
        sh(csprintf("qemu-img convert -f raw -O qcow2 %s pattern.raw %s",
                    extraOpts, name));
    }

    std::string dir;
};

/* A plain image with no backing file. */
TEST_F(Qcow2ImageTest, SingleLayer)
{
    makePatternedBase("a.qcow2");
    sh("qemu-io -c 'discard 1M 256k' a.qcow2");

    expectMatchesQemu("a.qcow2");

    Qcow2Image img("test", p("a.qcow2"), {}, 1 << 20, 16);
    img.open();
    EXPECT_EQ(img.depth(), 1u);
}

/*
 * A three-deep chain containing discarded regions. A discard leaves an
 * explicit zero cluster in the overlay, which must read as zeros rather than
 * falling through and resurrecting the data underneath.
 */
TEST_F(Qcow2ImageTest, ThreeDeepChainWithZeroClusters)
{
    makePatternedBase("base.qcow2");
    sh("qemu-img create -f qcow2 -b base.qcow2 -F qcow2 mid.qcow2");
    sh("qemu-io -c 'write -P 0xAA 1M 256k' mid.qcow2");
    sh("qemu-io -c 'discard 2M 512k' mid.qcow2");
    sh("qemu-img create -f qcow2 -b mid.qcow2 -F qcow2 top.qcow2");
    sh("qemu-io -c 'write -P 0x5A 3M 128k' top.qcow2");
    sh("qemu-io -c 'discard 512k 128k' top.qcow2");

    expectMatchesQemu("top.qcow2");

    Qcow2Image img("test", p("top.qcow2"), {}, 1 << 20, 16);
    img.open();
    EXPECT_EQ(img.depth(), 3u);
}

/* An overlay may be resized larger than the image it backs onto. */
TEST_F(Qcow2ImageTest, OverlayLargerThanBacking)
{
    makePatternedBase("base.qcow2");
    sh("qemu-img create -f qcow2 -b base.qcow2 -F qcow2 top.qcow2");
    sh("qemu-img resize top.qcow2 8M");
    sh("qemu-io -c 'write -P 0x77 6M 128k' top.qcow2");

    expectMatchesQemu("top.qcow2");

    Qcow2Image img("test", p("top.qcow2"), {}, 1 << 20, 16);
    img.open();
    EXPECT_EQ(img.size(), 8 * MiB);
}

/* A raw image terminates the chain. */
TEST_F(Qcow2ImageTest, RawBackingFile)
{
    makePatternedBase("tmp.qcow2");
    sh("qemu-img convert -f qcow2 -O raw tmp.qcow2 base.raw");
    sh("qemu-img create -f qcow2 -b base.raw -F raw top.qcow2");
    sh("qemu-io -c 'write -P 0x33 1M 64k' top.qcow2");

    expectMatchesQemu("top.qcow2");

    Qcow2Image img("test", p("top.qcow2"), {}, 1 << 20, 16);
    img.open();
    EXPECT_EQ(img.depth(), 2u);
}

/* zlib-compressed clusters, with an overlay on top. */
TEST_F(Qcow2ImageTest, ZlibCompressedChain)
{
    makePatternedBase("base.qcow2", "-c -o compression_type=zlib");
    sh("qemu-img create -f qcow2 -b base.qcow2 -F qcow2 top.qcow2");
    sh("qemu-io -c 'write -P 0xC1 1M 128k' top.qcow2");
    sh("qemu-io -c 'discard 2M 128k' top.qcow2");

    expectMatchesQemu("top.qcow2");
}

/* zstd-compressed clusters, when both qemu and gem5 support them. */
TEST_F(Qcow2ImageTest, ZstdCompressedChain)
{
#if !HAVE_LIBZSTD
    GTEST_SKIP() << "gem5 built without libzstd";
#else
    if (!haveCompression("zstd"))
        GTEST_SKIP() << "qemu-img has no zstd support";

    makePatternedBase("base.qcow2", "-c -o compression_type=zstd");
    sh("qemu-img create -f qcow2 -b base.qcow2 -F qcow2 top.qcow2");
    sh("qemu-io -c 'write -P 0xC2 1M 128k' top.qcow2");
    sh("qemu-io -c 'discard 2M 128k' top.qcow2");

    expectMatchesQemu("top.qcow2");
#endif
}

/* A backing file that has moved is found by basename via the search path. */
TEST_F(Qcow2ImageTest, BackingSearchPath)
{
    makePatternedBase("base.qcow2");
    sh("qemu-img create -f qcow2 -b base.qcow2 -F qcow2 top.qcow2");
    sh("qemu-io -c 'write -P 0x9E 1M 64k' top.qcow2");
    /* Move the backing file somewhere the recorded path will not find it. */
    sh("mkdir -p elsewhere && cp base.qcow2 elsewhere/base.qcow2");

    /* Ground truth first, while the recorded path still resolves. */
    sh("qemu-img convert -f qcow2 -O raw top.qcow2 truth.raw");
    sh("rm base.qcow2");

    Qcow2Image img("test", p("top.qcow2"), {p("elsewhere")}, 1 << 20, 16);
    img.open();
    EXPECT_EQ(img.depth(), 2u);

    std::ifstream truth(p("truth.raw"), std::ios::binary);
    std::vector<uint8_t> got(SECTOR), want(SECTOR);
    uint64_t mismatches = 0;
    for (uint64_t s = 0; s < img.size() / SECTOR; s++) {
        img.readSector(s * SECTOR, got.data());
        truth.read((char *)want.data(), SECTOR);
        if (got != want)
            mismatches++;
    }
    EXPECT_EQ(mismatches, 0u);
}

/* Reads stay correct once the L2 cache is small enough to thrash. */
TEST_F(Qcow2ImageTest, SurvivesL2CacheEviction)
{
    makePatternedBase("base.qcow2");
    sh("qemu-img create -f qcow2 -b base.qcow2 -F qcow2 top.qcow2");
    sh("qemu-io -c 'write -P 0xE7 1M 256k' top.qcow2");
    sh("qemu-img convert -f qcow2 -O raw top.qcow2 truth.raw");

    /* A budget far below one L2 table, forcing eviction on every lookup. */
    Qcow2Image img("test", p("top.qcow2"), {}, 8, 16);
    img.open();

    std::ifstream truth(p("truth.raw"), std::ios::binary);
    std::vector<uint8_t> got(SECTOR), want(SECTOR);
    uint64_t mismatches = 0;
    for (uint64_t s = 0; s < img.size() / SECTOR; s++) {
        img.readSector(s * SECTOR, got.data());
        truth.read((char *)want.data(), SECTOR);
        if (got != want)
            mismatches++;
    }
    EXPECT_EQ(mismatches, 0u);
}

/* reopen() rebuilds the chain and keeps serving the same data. */
TEST_F(Qcow2ImageTest, Reopen)
{
    makePatternedBase("base.qcow2");
    sh("qemu-img create -f qcow2 -b base.qcow2 -F qcow2 top.qcow2");
    sh("qemu-io -c 'write -P 0x6C 1M 64k' top.qcow2");

    expectMatchesQemu("top.qcow2");

    Qcow2Image img("test", p("top.qcow2"), {}, 1 << 20, 16);
    img.open();
    std::vector<uint8_t> before(SECTOR), after(SECTOR);
    img.readSector(MiB, before.data());

    img.reopen();
    EXPECT_EQ(img.depth(), 2u);
    img.readSector(MiB, after.data());
    EXPECT_EQ(before, after);
}

} // anonymous namespace
