#pragma once

#include "hash_path.hpp"
#include "mock_db.hpp"
#include "sha256_hasher.hpp"
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

/**
 * The MerkleTree class implements a Merkle tree—a data structure that enables efficient
 * proofs of membership.
 *
 * NOTE: This is a placeholder version. All helper methods and internal implementation details
 * have been removed. Replace the "// Implement" comments with the appropriate logic.
 */
class MerkleTree {
  private:
    static constexpr uint32_t MAX_DEPTH = 32;
    static constexpr uint32_t LEAF_BYTES = 64;
  public:
    /**
     * Constructs a new or existing tree.
     *
     * @param db The underlying database.
     * @param name The name of the tree.
     * @param depth The tree’s depth (with leaves at layer = depth).
     * @param root (Optional) The pre-existing tree root.
     *
     * Throws std::runtime_error if depth is not in [1, 32].
     */
    MerkleTree(MockDB& db, const std::string& name, uint32_t depth, const sha256_hash_t& root = {})
        : db(db)
        , name(name)
        , depth(depth)
        , root(root)
        , hasher()
    {
        // Validate the tree depth.
        if (!(depth >= 1 && depth <= MAX_DEPTH)) {
            throw std::runtime_error("Bad depth: Must be between 1 and 32.");
        }

        // Pre-compute the "zero hash" for each level of the tree.
        // These are the default hashes for nodes that haven't been set.
        zero_hashes.resize(depth + 1);
        zero_hashes[depth] = hasher.hash(std::vector<uint8_t>(LEAF_BYTES, 0));
        for (int i = depth - 1; i >= 0; --i) {
            std::vector<uint8_t> combined;
            combined.insert(combined.end(), zero_hashes[i+1].begin(), zero_hashes[i+1].end());
            combined.insert(combined.end(), zero_hashes[i+1].begin(), zero_hashes[i+1].end());
            zero_hashes[i] = hasher.hash(combined);
        }

        // If the root is the default (all zeros), this is a new tree.
        // Its root should be the pre-computed "zero root" for this depth.
        if (this->root == sha256_hash_t{}) {
            this->root = zero_hashes[0];
        }
    }

    /**
     * Creates (or restores) a MerkleTree instance.
     *
     * @param db The underlying database.
     * @param name The name of the tree.
     * @param depth The tree’s depth (default is 32).
     * @return A MerkleTree instance.
     */
    static MerkleTree create(MockDB& db, const std::string& name, uint32_t depth = MAX_DEPTH)
    {
        return MerkleTree(db, name, depth);
    }

    /**
     * Returns the current Merkle tree root (32 bytes).
     */
    sha256_hash_t get_root() const
    {
        return root;
    }

    /**
     * Returns the hash path (Merkle proof) for a particular leaf index.
     *
     * @param index The leaf index.
     * @return A HashPath object.
     */
    HashPath get_hash_path(uint64_t index) const
    {
        // Implement.
        //return HashPath();
        if (index >= (1ULL << depth)) {
            throw std::runtime_error("Index out of bounds for the given depth.");
        }

        HashPath path;
        path.data.reserve(depth);
        uint64_t current_index = index;

        // Traverse from leaf level up to the root's children.
        for (uint32_t level = depth; level > 0; --level) {
            // Find the parent index for the current node.
            uint64_t parent_index = current_index / 2;
            
            // Get the hashes of the two children of that parent.
            sha256_hash_t left_child = getNode(level, parent_index * 2);
            sha256_hash_t right_child = getNode(level, parent_index * 2 + 1);
            
            // Add the pair to the path.
            path.data.emplace_back(left_child, right_child);
            
            // Move up to the parent for the next iteration.
            current_index = parent_index;
        }

        // The path should be built from leaf to root, so we reverse it.
        //std::reverse(path.data.begin(), path.data.end());
        return path;
    }

    /**
     * Updates the leaf at the given index with the specified 64-byte value.
     *
     * @param index The index of the leaf.
     * @param value A 64-byte vector representing the leaf data.
     * @return The new 32-byte tree root.
     *
     * Throws std::runtime_error if value is not exactly 64 bytes.
     */
    //sha256_hash_t update_element(uint64_t index, const std::vector<uint8_t>& value)
    //{
    //    Implement.
    //    return root;
   //}

   sha256_hash_t update_element(uint64_t index, const std::vector<uint8_t>& value)
    {
        if (value.size() != LEAF_BYTES) {
            throw std::runtime_error("Leaf value must be exactly 64 bytes.");
        }

        if (index >= (1ULL << depth)) {
            throw std::runtime_error("Index out of bounds.");
        }

        std::vector<MockDBBatchItem> batch;

        // Step 1: Hash the leaf value.
        sha256_hash_t current_hash = hasher.hash(value);

        // Store it in the DB at leaf level.
        batch.push_back({ make_key(depth, index), current_hash });

        uint64_t current_index = index;

        // Step 2: Propagate up the tree
        for (uint32_t level = depth; level > 0; --level) {
            uint64_t sibling_index = current_index ^ 1; // if current is even, sibling is odd, and vice versa
            uint64_t parent_index = current_index / 2;

            sha256_hash_t left, right;

            if (current_index % 2 == 0) {
                left = current_hash;
                right = getNode(level, sibling_index);
            } else {
                left = getNode(level, sibling_index);
                right = current_hash;
            }

            // Combine and hash
            //std::vector<uint8_t> combined;
            //combined.insert(combined.end(), left.begin(), left.end());
            //combined.insert(combined.end(), right.begin(), right.end());
            //current_hash = hasher.hash(combined);
            current_hash = hasher.compress(left, right);

            batch.push_back({ make_key(level - 1, parent_index), current_hash });

            current_index = parent_index;
        }

        // Step 3: Update root
        root = current_hash;

        // Step 4: Write all updated nodes to the DB
        db.batch_write(batch);

        return root;
    }

    void add_leaf(uint64_t index, const std::vector<uint8_t>& leaf_data) {
            if (leaf_data.size() != 64) {
                throw std::runtime_error("Leaf data must be exactly 64 bytes");
            }
            if (index >= (1ULL << depth)) {
                throw std::runtime_error("Index out of bounds for tree depth");
            }

            sha256_hash_t leaf_hash = hasher.hash(leaf_data);
            db.put(make_key(depth, index), leaf_hash);
        }

    sha256_hash_t build_tree() {
        for (int level = depth - 1; level >= 0; --level) {
            uint64_t width = 1ULL << level;
            for (uint64_t index = 0; index < width; ++index) {
                auto left = getNode(level + 1, index * 2);
                auto right = getNode(level + 1, index * 2 + 1);
                auto parent = hasher.compress(left, right);
                db.put(make_key(level, index), parent);
            }
        }
        root = getNode(0, 0);
        return root;
    }

    MockDB& get_db() { return db ;}

  private:

      /**
     * Generates a unique key for a node based on its level and index.
     */
    std::string make_key(uint32_t level, uint64_t index) const {
        return name + ":" + std::to_string(level) + ":" + std::to_string(index);
    }


    /**
     * Retrieves a node's hash. If not found in the DB, returns the
     * pre-computed zero hash for that level.
     */
    sha256_hash_t getNode(uint32_t level, uint64_t index) const {
        //sha256_hash_t node_hash;
        auto value_opt = db.get(make_key(level, index));
        if (value_opt) {
            return *value_opt;
        } 
        return zero_hashes.at(level);
    }
    // Core member variables.
    MockDB& db;
    std::string name;
    uint32_t depth;
    sha256_hash_t root;
    Sha256Hasher hasher;
    std::vector<sha256_hash_t> zero_hashes;
};
