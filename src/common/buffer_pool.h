#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <mutex>

namespace proxy {

// Fixed-size memory block pool for zero-copy buffer management
class BufferPool {
public:
    // Block size: 64KB - suitable for typical I/O operations
    static constexpr std::size_t kBlockSize = 64 * 1024;

    struct Block {
        uint8_t* data;
        std::size_t used;  // Number of valid bytes in this block
    };

    explicit BufferPool(std::size_t max_blocks = 256);
    ~BufferPool();

    BufferPool(const BufferPool&) = delete;
    BufferPool& operator=(const BufferPool&) = delete;

    // Acquire a block (from pool or newly allocated)
    // Returns nullptr if max_blocks limit reached
    Block* acquire();

    // Release a block back to the pool
    void release(Block* block);

    // Get current statistics
    std::size_t available_blocks() const;
    std::size_t total_blocks() const;

private:
    std::size_t max_blocks_;
    std::vector<std::unique_ptr<uint8_t[]>> storage_;  // Ownership of data
    std::vector<Block> all_blocks_;                     // Metadata for all blocks
    std::vector<Block*> free_list_;                     // Available blocks

    mutable std::mutex mutex_;

    Block* allocate_new_block();
};

}  // namespace proxy
