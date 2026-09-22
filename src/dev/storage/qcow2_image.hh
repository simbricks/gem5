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
 * Read-only qcow2 image reader, including backing chains.
 *
 * This is deliberately free of any SimObject dependency so that it can be
 * exercised directly from unit tests.
 */

#ifndef __DEV_STORAGE_QCOW2_IMAGE_HH__
#define __DEV_STORAGE_QCOW2_IMAGE_HH__

#include <cstdint>
#include <functional>
#include <list>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace gem5
{

/**
 * A qcow2 image together with its backing chain, opened read-only.
 *
 * The chain is resolved in open() by following the backing file pointers
 * recorded in the image headers, so backing layers are plain structures
 * rather than separate objects.
 */
class Qcow2Image
{
  public:
    /** Sector size used by the read interface. */
    static const uint64_t SectorBytes = 512;

    /**
     * Called when a read falls through from one layer to the next, for
     * tracing. Optional; ignored when unset.
     */
    typedef std::function<void(size_t depth, const std::string &file,
                               uint64_t cluster, const char *why)>
        DescendHook;

    /**
     * @param label Prefix for diagnostics, e.g. the owning SimObject's name.
     * @param file Path to the top image.
     * @param searchPath Directories searched by basename when a recorded
     *        backing file does not resolve.
     * @param l2CacheBytes Budget for cached L2 tables, shared across layers.
     * @param maxChainDepth Refuse chains deeper than this.
     */
    Qcow2Image(const std::string &label, const std::string &file,
               const std::vector<std::string> &searchPath,
               uint64_t l2CacheBytes, int maxChainDepth);
    ~Qcow2Image();

    /** Open the image and resolve its backing chain. Fatal on error. */
    void open();
    void close();
    /** close() followed by open(); drops all cached state. */
    void reopen();

    /** Virtual size of the top overlay, in bytes. */
    uint64_t size() const;
    /** Number of layers in the resolved chain. */
    size_t depth() const { return chain.size(); }
    /** Path of layer i, chain[0] being the top overlay. */
    const std::string &layerName(size_t i) const;
    /** Human-readable chain listing, for diagnostics. */
    std::string chainDescription() const;

    void setDescendHook(DescendHook hook) { descendHook = std::move(hook); }

    /** Read one sector. @param voff byte offset, sector-aligned. */
    void readSector(uint64_t voff, uint8_t *data) const;

  private:
    /** Compression algorithm used by a layer's compressed clusters. */
    enum CompressionType
    {
        COMPRESSION_ZLIB = 0,
        COMPRESSION_ZSTD = 1,
    };

    /** One image in the backing chain. chain[0] is the top overlay. */
    struct Layer
    {
        std::string filename;
        int fd = -1;
        /** A raw image terminates the chain and has no metadata. */
        bool raw = false;
        uint64_t virtualSize = 0;

        /* qcow2 geometry; unused when raw. */
        uint32_t clusterBits = 0;
        uint64_t clusterSize = 0;
        /** clusterSize - 1, for extracting the offset within a cluster. */
        uint64_t clusterMask = 0;
        uint64_t l2Entries = 0;
        uint32_t l1Size = 0;
        uint64_t l1Offset = 0;
        std::vector<uint64_t> l1;

        /* Geometry of the compressed cluster descriptor. */
        uint32_t csizeShift = 0;
        uint64_t csizeMask = 0;
        uint64_t clusterOffsetMask = 0;
        CompressionType compressionType = COMPRESSION_ZLIB;
    };

    /** Cache key: index of the layer, host byte offset within it. */
    typedef std::pair<size_t, uint64_t> CacheKey;

    struct CacheKeyHash
    {
        size_t
        operator()(const CacheKey &k) const
        {
            return std::hash<uint64_t>()(k.second) ^ (k.first * 0x9e3779b9);
        }
    };

    /**
     * Minimal LRU cache with a budget expressed in bytes, so that a single
     * budget can be shared across chain layers with differing cluster sizes.
     */
    template <typename V>
    class LruCache
    {
      public:
        typedef std::list<std::pair<CacheKey, V>> List;

        void
        setBudget(uint64_t bytes)
        {
            budget = bytes;
        }

        const V *
        find(const CacheKey &key)
        {
            auto it = map.find(key);
            if (it == map.end())
                return nullptr;
            lru.splice(lru.begin(), lru, it->second);
            return &lru.begin()->second;
        }

        /** Insert and return a pointer to the stored value. */
        const V *
        insert(const CacheKey &key, V &&value, uint64_t bytes)
        {
            lru.emplace_front(key, std::move(value));
            map[key] = lru.begin();
            used += bytes;
            sizes[key] = bytes;

            // Never evict the entry just inserted, even if it alone exceeds
            // the budget; the caller is about to dereference it.
            while (used > budget && lru.size() > 1) {
                auto &victim = lru.back();
                used -= sizes[victim.first];
                sizes.erase(victim.first);
                map.erase(victim.first);
                lru.pop_back();
            }

            return &lru.begin()->second;
        }

        void
        clear()
        {
            lru.clear();
            map.clear();
            sizes.clear();
            used = 0;
        }

      private:
        List lru;
        std::unordered_map<CacheKey, typename List::iterator, CacheKeyHash>
            map;
        std::unordered_map<CacheKey, uint64_t, CacheKeyHash> sizes;
        uint64_t budget = 0;
        uint64_t used = 0;
    };

    /* Chain construction. */
    void openChain();
    void closeChain();
    void openLayer(Layer &layer, const std::string &path,
                   const std::string &format, std::string &backingRecorded,
                   std::string &backingFormat);
    void parseHeader(Layer &layer, std::string &backingRecorded,
                     std::string &backingFormat);
    std::string resolveBacking(const std::string &parent,
                               const std::string &recorded) const;

    /* Read path. */
    void readSector(size_t depth, uint64_t voff, uint8_t *data) const;
    const std::vector<uint64_t> *getL2(size_t depth, uint64_t tableOffset)
        const;
    const std::vector<uint8_t> *getCompressedCluster(size_t depth,
                                                     uint64_t l2e) const;
    void decompressCluster(const Layer &layer, const uint8_t *in,
                           uint64_t inLen, uint8_t *out) const;
    void decompressZlib(const Layer &layer, const uint8_t *in,
                        uint64_t inLen, uint8_t *out) const;
    void decompressZstd(const Layer &layer, const uint8_t *in,
                        uint64_t inLen, uint8_t *out) const;
    void readAt(const Layer &layer, void *buf, uint64_t len,
                uint64_t offset) const;

    std::string label;
    std::string imageFile;
    std::vector<std::string> backingSearchPath;
    uint64_t l2CacheBytes;
    int maxChainDepth;

    std::vector<Layer> chain;

    DescendHook descendHook;

    mutable LruCache<std::vector<uint64_t>> l2Cache;
    mutable LruCache<std::vector<uint8_t>> clusterCache;
};

} // namespace gem5

#endif // __DEV_STORAGE_QCOW2_IMAGE_HH__
