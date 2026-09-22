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

#include "dev/storage/qcow2_image.hh"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <set>

#include "base/cprintf.hh"
#include "base/logging.hh"
#include "config/have_libzstd.hh"

#if HAVE_LIBZSTD
#include <zstd.h>
#endif

namespace gem5
{

namespace
{

/* Header field offsets, per the qcow2 specification. */
constexpr uint64_t QCOW2_MAGIC = 0x514649fbULL;
constexpr uint32_t HDR_V2_LENGTH = 72;
/* The compression_type byte lives in the header proper, after the v3 base. */
constexpr uint32_t HDR_COMPRESSION_TYPE_OFF = 104;

/* Header extension identifiers. */
constexpr uint32_t EXT_END = 0x00000000;
constexpr uint32_t EXT_BACKING_FORMAT = 0xE2792ACA;

/* incompatible_features bits. */
constexpr uint64_t INCOMPAT_DIRTY = 1ULL << 0;
constexpr uint64_t INCOMPAT_CORRUPT = 1ULL << 1;
constexpr uint64_t INCOMPAT_DATA_FILE = 1ULL << 2;
constexpr uint64_t INCOMPAT_COMPRESSION = 1ULL << 3;
constexpr uint64_t INCOMPAT_EXTL2 = 1ULL << 4;
constexpr uint64_t INCOMPAT_KNOWN =
    INCOMPAT_DIRTY | INCOMPAT_CORRUPT | INCOMPAT_DATA_FILE |
    INCOMPAT_COMPRESSION | INCOMPAT_EXTL2;

/* L1/L2 entry layout. */
constexpr uint64_t L1E_OFFSET_MASK = 0x00fffffffffffe00ULL;
constexpr uint64_t L2E_OFFSET_MASK = 0x00fffffffffffe00ULL;
constexpr uint64_t OFLAG_COMPRESSED = 1ULL << 62;
constexpr uint64_t OFLAG_ZERO = 1ULL << 0;

/* Compressed cluster descriptors are measured in 512-byte units. */
constexpr uint64_t COMPRESSED_SECTOR_BYTES = 512;

constexpr uint32_t MIN_CLUSTER_BITS = 9;
constexpr uint32_t MAX_CLUSTER_BITS = 21;

/* Unaligned big-endian loads; header buffers are read as raw bytes. */
uint32_t
be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint64_t
be64(const uint8_t *p)
{
    return ((uint64_t)be32(p) << 32) | (uint64_t)be32(p + 4);
}

} // anonymous namespace

Qcow2Image::Qcow2Image(const std::string &_label,
                       const std::string &file,
                       const std::vector<std::string> &searchPath,
                       uint64_t _l2CacheBytes, int _maxChainDepth)
    : label(_label),
      imageFile(file),
      backingSearchPath(searchPath),
      l2CacheBytes(_l2CacheBytes),
      maxChainDepth(_maxChainDepth)
{
}

Qcow2Image::~Qcow2Image()
{
    closeChain();
}

void
Qcow2Image::open()
{
    if (imageFile.empty())
        fatal("%s: image_file must be set", label);

    if (maxChainDepth < 1)
        fatal("%s: max_chain_depth must be at least 1", label);

    l2Cache.setBudget(l2CacheBytes);
    /*
     * Decompressed clusters get a small fixed cache of their own rather than
     * a share of l2CacheBytes: compression is uncommon in practice, and
     * conflating the two would let a compressed region evict the L2 tables
     * that every read depends on.
     */
    clusterCache.setBudget(4 * (1ULL << MAX_CLUSTER_BITS));

    openChain();
}

void
Qcow2Image::close()
{
    closeChain();
}

void
Qcow2Image::reopen()
{
    closeChain();
    open();
}

uint64_t
Qcow2Image::size() const
{
    /*
     * The top overlay governs. An overlay may legally be larger than the
     * image it backs onto, so the child's size is never consulted here.
     */
    return chain[0].virtualSize;
}

const std::string &
Qcow2Image::layerName(size_t i) const
{
    return chain.at(i).filename;
}

std::string
Qcow2Image::chainDescription() const
{
    std::string out;
    for (size_t i = 0; i < chain.size(); i++) {
        out += csprintf("\n    [%d] %s (%s)", i, chain[i].filename,
                        chain[i].raw ? "raw" : "qcow2");
    }
    return out;
}

void
Qcow2Image::readSector(uint64_t voff, uint8_t *data) const
{
    readSector(0, voff, data);
}

void
Qcow2Image::closeChain()
{
    for (auto &layer : chain) {
        if (layer.fd >= 0)
            ::close(layer.fd);
    }
    chain.clear();
    l2Cache.clear();
    clusterCache.clear();
}

void
Qcow2Image::openChain()
{
    std::string path = imageFile;
    /* Empty means "probe by magic"; the top image is always probed. */
    std::string format;
    std::set<std::string> seen;

    while (true) {
        if ((int)chain.size() >= maxChainDepth) {
            fatal("%s: backing chain deeper than max_chain_depth=%d, "
                  "starting at %s. Chain so far:%s", label, maxChainDepth,
                  imageFile, chainDescription());
        }

        std::error_code ec;
        std::string canonical =
            std::filesystem::weakly_canonical(path, ec).string();
        if (ec)
            canonical = path;
        if (!seen.insert(canonical).second) {
            fatal("%s: backing chain loops back to %s. Chain so far:%s",
                  label, path, chainDescription());
        }

        Layer layer;
        std::string backingRecorded;
        std::string backingFormat;
        openLayer(layer, path, format, backingRecorded, backingFormat);

        bool isRaw = layer.raw;
        std::string thisPath = layer.filename;
        chain.push_back(std::move(layer));

        /* A raw image has no backing pointer and terminates the chain. */
        if (isRaw || backingRecorded.empty())
            break;

        path = resolveBacking(thisPath, backingRecorded);
        format = backingFormat;
    }

}

void
Qcow2Image::openLayer(Layer &layer, const std::string &path,
                          const std::string &format,
                          std::string &backingRecorded,
                          std::string &backingFormat)
{
    layer.filename = path;
    layer.fd = ::open(path.c_str(), O_RDONLY);
    if (layer.fd < 0) {
        fatal("%s: could not open %s: %s. Chain so far:%s", label, path,
              strerror(errno), chainDescription());
    }

    std::string fmt = format;
    if (fmt.empty()) {
        /* No recorded format: probe the magic. */
        uint8_t magic[4] = {0, 0, 0, 0};
        ssize_t n = ::pread(layer.fd, magic, sizeof(magic), 0);
        fmt = (n == (ssize_t)sizeof(magic) && be32(magic) == QCOW2_MAGIC)
                  ? "qcow2"
                  : "raw";
    }

    if (fmt == "raw") {
        struct stat st;
        if (::fstat(layer.fd, &st) < 0) {
            fatal("%s: could not stat %s: %s", label, path,
                  strerror(errno));
        }
        layer.raw = true;
        layer.virtualSize = (uint64_t)st.st_size;
        backingRecorded.clear();
        backingFormat.clear();
        return;
    }

    if (fmt != "qcow2") {
        fatal("%s: backing file %s has format '%s', which is not supported; "
              "only 'qcow2' and 'raw' are. Chain so far:%s", label, path,
              fmt, chainDescription());
    }

    parseHeader(layer, backingRecorded, backingFormat);
}

void
Qcow2Image::parseHeader(Layer &layer, std::string &backingRecorded,
                            std::string &backingFormat)
{
    uint8_t hdr[HDR_COMPRESSION_TYPE_OFF + 1];
    readAt(layer, hdr, HDR_V2_LENGTH, 0);

    if (be32(hdr) != QCOW2_MAGIC)
        fatal("%s: %s is not a qcow2 image", label, layer.filename);

    uint32_t version = be32(hdr + 4);
    if (version < 2 || version > 3) {
        fatal("%s: %s has qcow2 version %d; only 2 and 3 are supported",
              label, layer.filename, version);
    }

    uint64_t backingOffset = be64(hdr + 8);
    uint32_t backingSize = be32(hdr + 16);
    layer.clusterBits = be32(hdr + 20);
    layer.virtualSize = be64(hdr + 24);
    uint32_t cryptMethod = be32(hdr + 32);
    layer.l1Size = be32(hdr + 36);
    layer.l1Offset = be64(hdr + 40);

    if (layer.clusterBits < MIN_CLUSTER_BITS ||
        layer.clusterBits > MAX_CLUSTER_BITS) {
        fatal("%s: %s has cluster_bits=%d, outside the supported range "
              "[%d, %d]", label, layer.filename, layer.clusterBits,
              MIN_CLUSTER_BITS, MAX_CLUSTER_BITS);
    }

    if (cryptMethod != 0) {
        fatal("%s: %s is encrypted (crypt_method=%d); encrypted images are "
              "not supported", label, layer.filename, cryptMethod);
    }

    layer.clusterSize = 1ULL << layer.clusterBits;
    layer.clusterMask = layer.clusterSize - 1;
    layer.l2Entries = layer.clusterSize / sizeof(uint64_t);
    layer.csizeShift = 62 - (layer.clusterBits - 8);
    layer.csizeMask = (1ULL << (layer.clusterBits - 8)) - 1;
    layer.clusterOffsetMask = (1ULL << layer.csizeShift) - 1;

    uint32_t headerLength = HDR_V2_LENGTH;

    if (version >= 3) {
        readAt(layer, hdr, 104, 0);
        uint64_t incompatible = be64(hdr + 72);
        headerLength = be32(hdr + 100);

        if (incompatible & ~INCOMPAT_KNOWN) {
            fatal("%s: %s sets unknown incompatible_features bits 0x%x; "
                  "refusing to open rather than risk misreading it", label,
                  layer.filename, incompatible & ~INCOMPAT_KNOWN);
        }
        if (incompatible & INCOMPAT_CORRUPT) {
            fatal("%s: %s is marked corrupt; repair it with 'qemu-img check "
                  "-r' first", label, layer.filename);
        }
        if (incompatible & INCOMPAT_DATA_FILE) {
            fatal("%s: %s uses an external data file, which is not "
                  "supported", label, layer.filename);
        }
        if (incompatible & INCOMPAT_EXTL2) {
            fatal("%s: %s uses extended L2 entries (subcluster allocation), "
                  "which is not supported", label, layer.filename);
        }
        if (incompatible & INCOMPAT_DIRTY) {
            /*
             * Dirty means the refcounts may be stale. Reads never consult
             * refcounts, so this is harmless for us, but it does mean the
             * image was not closed cleanly.
             */
            warn("%s: %s is marked dirty; opening read-only anyway",
                 label, layer.filename);
        }

        if (incompatible & INCOMPAT_COMPRESSION) {
            if (headerLength <= HDR_COMPRESSION_TYPE_OFF) {
                fatal("%s: %s sets the compression-type feature but its "
                      "header is only %d bytes", label, layer.filename,
                      headerLength);
            }
            readAt(layer, hdr, HDR_COMPRESSION_TYPE_OFF + 1, 0);
            uint8_t ctype = hdr[HDR_COMPRESSION_TYPE_OFF];
            if (ctype != COMPRESSION_ZLIB && ctype != COMPRESSION_ZSTD) {
                fatal("%s: %s declares unknown compression type %d", label,
                      layer.filename, ctype);
            }
#if !HAVE_LIBZSTD
            if (ctype == COMPRESSION_ZSTD) {
                fatal("%s: %s uses zstd cluster compression, but gem5 was "
                      "built without libzstd. Install libzstd development "
                      "headers and rebuild, or convert the image with "
                      "'qemu-img convert -o compression_type=zlib'.",
                      label, layer.filename);
            }
#endif
            layer.compressionType = (CompressionType)ctype;
        }
    }

    /* Read the L1 table. */
    if (layer.l1Size) {
        std::vector<uint8_t> raw((size_t)layer.l1Size * sizeof(uint64_t));
        readAt(layer, raw.data(), raw.size(), layer.l1Offset);
        layer.l1.resize(layer.l1Size);
        for (uint32_t i = 0; i < layer.l1Size; i++)
            layer.l1[i] = be64(raw.data() + i * sizeof(uint64_t));
    }

    /* Backing file name, if any. */
    backingRecorded.clear();
    if (backingOffset && backingSize) {
        std::vector<char> buf(backingSize);
        readAt(layer, buf.data(), backingSize, backingOffset);
        backingRecorded.assign(buf.data(), backingSize);
    }

    /*
     * Walk the header extensions for the recorded backing format. Absent it,
     * the backing file is probed by magic, matching qemu's behaviour.
     */
    backingFormat.clear();
    uint64_t pos = headerLength;
    while (true) {
        uint8_t ext[8];
        readAt(layer, ext, sizeof(ext), pos);
        uint32_t type = be32(ext);
        uint32_t len = be32(ext + 4);
        if (type == EXT_END)
            break;
        if (type == EXT_BACKING_FORMAT) {
            std::vector<char> buf(len);
            readAt(layer, buf.data(), len, pos + 8);
            backingFormat.assign(buf.data(), len);
        }
        /* Extension payloads are padded to an 8-byte boundary. */
        pos += 8 + ((len + 7) & ~7ULL);
    }
}

std::string
Qcow2Image::resolveBacking(const std::string &parent,
                               const std::string &recorded) const
{
    namespace fs = std::filesystem;
    std::error_code ec;

    fs::path rec(recorded);
    fs::path candidate;

    if (rec.is_absolute()) {
        candidate = rec;
    } else {
        /* Relative backing paths are relative to the referring image. */
        candidate = fs::path(parent).parent_path() / rec;
    }

    if (fs::exists(candidate, ec))
        return candidate.string();

    /* Fall back to searching by basename. */
    for (const auto &dir : backingSearchPath) {
        fs::path alt = fs::path(dir) / rec.filename();
        if (fs::exists(alt, ec))
            return alt.string();
    }

    std::string searched;
    for (const auto &dir : backingSearchPath)
        searched += csprintf("\n    %s", dir);
    if (backingSearchPath.empty())
        searched = " (none configured; see --disk-backing-path)";

    fatal("%s: %s records backing file '%s', which does not resolve.\n"
          "  Tried: %s\n"
          "  Search path by basename '%s':%s\n"
          "  Chain so far:%s",
          label, parent, recorded, candidate.string(),
          rec.filename().string(), searched, chainDescription());
}

void
Qcow2Image::readAt(const Layer &layer, void *buf, uint64_t len,
                       uint64_t offset) const
{
    uint8_t *p = (uint8_t *)buf;
    uint64_t done = 0;

    while (done < len) {
        ssize_t n = ::pread(layer.fd, p + done, len - done, offset + done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            fatal("%s: read of %d bytes at %d in %s failed: %s", label, len,
                  offset, layer.filename, strerror(errno));
        }
        if (n == 0) {
            fatal("%s: unexpected end of file reading %d bytes at %d in %s; "
                  "the image is truncated or the metadata is inconsistent",
                  label, len, offset, layer.filename);
        }
        done += n;
    }
}

const std::vector<uint64_t> *
Qcow2Image::getL2(size_t depth, uint64_t tableOffset) const
{
    CacheKey key(depth, tableOffset);
    if (const auto *hit = l2Cache.find(key))
        return hit;

    const Layer &layer = chain[depth];
    std::vector<uint8_t> raw(layer.clusterSize);
    readAt(layer, raw.data(), layer.clusterSize, tableOffset);

    std::vector<uint64_t> table(layer.l2Entries);
    for (uint64_t i = 0; i < layer.l2Entries; i++)
        table[i] = be64(raw.data() + i * sizeof(uint64_t));

    return l2Cache.insert(key, std::move(table),
                          layer.l2Entries * sizeof(uint64_t));
}

const std::vector<uint8_t> *
Qcow2Image::getCompressedCluster(size_t depth, uint64_t l2e) const
{
    const Layer &layer = chain[depth];

    uint64_t coffset = l2e & layer.clusterOffsetMask;
    uint64_t nbSectors = ((l2e >> layer.csizeShift) & layer.csizeMask) + 1;
    /*
     * The compressed extent is measured in 512-byte units from the sector
     * containing coffset, so the leading partial sector is subtracted.
     */
    uint64_t csize = nbSectors * COMPRESSED_SECTOR_BYTES -
                     (coffset & (COMPRESSED_SECTOR_BYTES - 1));

    CacheKey key(depth, coffset);
    if (const auto *hit = clusterCache.find(key))
        return hit;

    std::vector<uint8_t> in(csize);
    readAt(layer, in.data(), csize, coffset);

    std::vector<uint8_t> out(layer.clusterSize);
    decompressCluster(layer, in.data(), csize, out.data());

    return clusterCache.insert(key, std::move(out), layer.clusterSize);
}

void
Qcow2Image::decompressCluster(const Layer &layer, const uint8_t *in,
                                  uint64_t inLen, uint8_t *out) const
{
    switch (layer.compressionType) {
      case COMPRESSION_ZLIB:
        decompressZlib(layer, in, inLen, out);
        return;
      case COMPRESSION_ZSTD:
        decompressZstd(layer, in, inLen, out);
        return;
      default:
        fatal("%s: %s declares unknown compression type %d", label,
              layer.filename, (int)layer.compressionType);
    }
}

void
Qcow2Image::decompressZlib(const Layer &layer, const uint8_t *in,
                               uint64_t inLen, uint8_t *out) const
{
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.next_in = (Bytef *)in;
    strm.avail_in = inLen;
    strm.next_out = (Bytef *)out;
    strm.avail_out = layer.clusterSize;

    /* qcow2 stores raw deflate streams with a 4KiB window. */
    int ret = inflateInit2(&strm, -12);
    if (ret != Z_OK) {
        fatal("%s: could not initialise zlib for %s: %d", label,
              layer.filename, ret);
    }

    ret = inflate(&strm, Z_FINISH);
    /*
     * Z_BUF_ERROR is accepted alongside Z_STREAM_END: the compressed length
     * is only known to 512-byte precision, so zlib may still have input left
     * once the cluster is fully reconstructed. What matters is that the
     * output buffer was filled.
     */
    bool ok = (ret == Z_STREAM_END || ret == Z_BUF_ERROR) &&
              strm.avail_out == 0;
    uint64_t missing = strm.avail_out;
    inflateEnd(&strm);

    if (!ok) {
        fatal("%s: failed to decompress a zlib cluster in %s (zlib returned "
              "%d, %d bytes short)", label, layer.filename, ret, missing);
    }
}

void
Qcow2Image::decompressZstd(const Layer &layer, const uint8_t *in,
                               uint64_t inLen, uint8_t *out) const
{
#if !HAVE_LIBZSTD
    fatal("%s: %s uses zstd cluster compression, but gem5 was built without "
          "libzstd", label, layer.filename);
#else
    ZSTD_DStream *dctx = ZSTD_createDStream();
    if (!dctx) {
        fatal("%s: could not allocate a zstd decompression context for %s",
              label, layer.filename);
    }

    ZSTD_inBuffer input = { in, (size_t)inLen, 0 };
    ZSTD_outBuffer output = { out, (size_t)layer.clusterSize, 0 };
    const char *err = nullptr;

    /*
     * The compressed extent may hold more than one zstd frame, so iterate
     * until the cluster is fully reconstructed. As with zlib, the extent
     * length is only known to 512-byte precision, so trailing bytes beyond
     * the last frame are expected and simply left unconsumed.
     */
    while (output.pos < output.size) {
        size_t lastIn = input.pos;
        size_t lastOut = output.pos;

        size_t ret = ZSTD_decompressStream(dctx, &output, &input);

        if (ZSTD_isError(ret)) {
            err = ZSTD_getErrorName(ret);
            break;
        }

        /*
         * Neither buffer advanced, so no further progress is possible: the
         * stream is truncated or the recorded extent is wrong. Without this
         * check the loop would spin forever.
         */
        if (lastIn >= input.pos && lastOut >= output.pos) {
            err = "no progress; truncated or inconsistent compressed extent";
            break;
        }
    }

    ZSTD_freeDStream(dctx);

    if (err) {
        fatal("%s: failed to decompress a zstd cluster in %s: %s (%d of %d "
              "bytes recovered)", label, layer.filename, err, output.pos,
              output.size);
    }
#endif
}

void
Qcow2Image::readSector(size_t depth, uint64_t voff, uint8_t *data) const
{
    /* Ran off the end of the chain: nothing backs this region. */
    if (depth >= chain.size()) {
        memset(data, 0, SectorBytes);
        return;
    }

    const Layer &layer = chain[depth];

    /*
     * A backing image may be shorter than the overlay in front of it, in
     * which case the region past its end reads as zeros rather than being
     * an error.
     */
    if (voff >= layer.virtualSize) {
        memset(data, 0, SectorBytes);
        return;
    }

    if (layer.raw) {
        readAt(layer, data, SectorBytes, voff);
        return;
    }

    uint64_t cluster = voff >> layer.clusterBits;
    uint64_t l1Index = cluster / layer.l2Entries;
    uint64_t l2Index = cluster % layer.l2Entries;

    if (l1Index >= layer.l1Size) {
        readSector(depth + 1, voff, data);
        return;
    }

    uint64_t l1e = layer.l1[l1Index] & L1E_OFFSET_MASK;
    if (l1e == 0) {
        if (descendHook)
            descendHook(depth, layer.filename, cluster, "no L2 table");
        readSector(depth + 1, voff, data);
        return;
    }

    const std::vector<uint64_t> *l2 = getL2(depth, l1e);
    uint64_t l2e = (*l2)[l2Index];

    /*
     * Order matters. The compressed flag must be tested first: for a
     * compressed descriptor the low bits are part of the host offset, so
     * checking the zero flag first would misread a compressed cluster whose
     * offset happens to have bit 0 set.
     */
    if (l2e & OFLAG_COMPRESSED) {
        const std::vector<uint8_t> *c = getCompressedCluster(depth, l2e);
        memcpy(data, c->data() + (voff & layer.clusterMask), SectorBytes);
        return;
    }

    /*
     * An explicit zero cluster reads as zeros and stops the descent. This is
     * distinct from an unallocated cluster: falling through to the backing
     * file here would resurrect data the overlay has discarded.
     */
    if (l2e & OFLAG_ZERO) {
        memset(data, 0, SectorBytes);
        return;
    }

    uint64_t host = l2e & L2E_OFFSET_MASK;
    if (host == 0) {
        if (descendHook)
            descendHook(depth, layer.filename, cluster, "unallocated");
        readSector(depth + 1, voff, data);
        return;
    }

    readAt(layer, data, SectorBytes, host + (voff & layer.clusterMask));
}

} // namespace gem5
