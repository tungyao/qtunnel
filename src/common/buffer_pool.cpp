#include "buffer_pool.h"

namespace proxy {

BufferPool::BufferPool(std::size_t max_blocks) : max_blocks_(max_blocks) {
    // Pre-allocate half of max_blocks for faster startup
    std::size_t initial_blocks = max_blocks / 2;
    for (std::size_t i = 0; i < initial_blocks; ++i) {
        auto* block = allocate_new_block();
        if (block) {
            free_list_.push_back(block);
        }
    }
}

BufferPool::~BufferPool() {
    // All blocks are freed automatically via unique_ptr
    storage_.clear();
    all_blocks_.clear();
    free_list_.clear();
}

BufferPool::Block* BufferPool::allocate_new_block() {
    if (all_blocks_.size() >= max_blocks_) {
        return nullptr;
    }

    // Allocate new data
    auto data = std::make_unique<uint8_t[]>(kBlockSize);
    uint8_t* data_ptr = data.get();

    // Store ownership
    storage_.push_back(std::move(data));

    // Create and store block metadata
    Block block;
    block.data = data_ptr;
    block.used = 0;
    all_blocks_.push_back(block);

    // Return pointer to the newly created block
    return &all_blocks_.back();
}

BufferPool::Block* BufferPool::acquire() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Try to get a free block
    if (!free_list_.empty()) {
        Block* block = free_list_.back();
        free_list_.pop_back();
        block->used = 0;  // Reset for reuse
        return block;
    }

    // Allocate a new block if under limit
    auto* block = allocate_new_block();
    if (block) {
        block->used = 0;
    }
    return block;
}

void BufferPool::release(Block* block) {
    if (!block) return;

    std::lock_guard<std::mutex> lock(mutex_);

    // Return block to free list if it's one of ours
    for (auto& stored_block : all_blocks_) {
        if (&stored_block == block) {
            block->used = 0;
            free_list_.push_back(block);
            return;
        }
    }
}

std::size_t BufferPool::available_blocks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return free_list_.size();
}

std::size_t BufferPool::total_blocks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return all_blocks_.size();
}

}  // namespace proxy
