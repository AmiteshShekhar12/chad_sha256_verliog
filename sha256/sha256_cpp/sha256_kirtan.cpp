#include <iostream>
#include <cstdint>
#include <string>
#include <vector>
#include <bitset>

// Helper Functions for SHA-256
inline std::uint32_t rotr(std::uint32_t num, std::uint32_t num_shift) { return (num >> num_shift) | (num << (32 - num_shift)); }

// Small Sigma and Big Sigma Functions
inline std::uint32_t small_sigma0(std::uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline std::uint32_t small_sigma1(std::uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }
inline std::uint32_t big_sigma0(std::uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline std::uint32_t big_sigma1(std::uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }

// Choice and Majority Functions
inline std::uint32_t choice(std::uint32_t decison, std::uint32_t choice1, std::uint32_t choice0) { return (decison & choice1) ^ (~decison & choice0); }
inline std::uint32_t majority(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

// Initial Hash Values for SHA-256
std::vector<std::uint32_t> InitializeHashValues() {
    return {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
}

// SHA-256 Constant Table
std::vector<std::uint32_t> InitializeConstants() {
    return {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
}

// Padding Function to prepare input message for processing
std::vector<std::bitset<8>> Padding(const std::string& input) {
    std::int64_t input_length = input.length();
    std::int64_t input_bits = input_length * 8;
    std::int64_t padded_bits = ((input_bits + 64 + 511) / 512) * 512;
    std::vector<std::bitset<8>> padded(padded_bits / 8, std::bitset<8>(0));

    // Add original message bytes
    for (std::int64_t i = 0; i < input_length; ++i) {
        padded[i] = std::bitset<8>(static_cast<unsigned char>(input[i]));
    }

    // Add 1 bit after the message
    padded[input_length] = std::bitset<8>(0b10000000);

    // Append original message length as 64-bit big-endian
    for (int i = 0; i < 8; ++i) {
        padded[padded.size() - 8 + i] = std::bitset<8>((input_bits >> (8 * (7 - i))) & 0xFF);
    }

    return padded;
}

// Segment message into 512-bit blocks of 16 32-bit words
std::vector<std::vector<std::uint32_t>> SegmentToBlocks(const std::vector<std::bitset<8>>& padded) {
    std::vector<std::vector<std::uint32_t>> blocks;

    for (size_t i = 0; i < padded.size(); i += 64) {
        std::vector<std::uint32_t> block(16, 0);
        for (size_t j = 0; j < 16; ++j) {
            block[j] = (padded[i + j * 4].to_ulong() << 24) | (padded[i + j * 4 + 1].to_ulong() << 16) |
                        (padded[i + j * 4 + 2].to_ulong() << 8) | (padded[i + j * 4 + 3].to_ulong());
        }
        blocks.push_back(block);
    }

    return blocks;
}

// Message Schedule Extension
void MessageSchedule(std::vector<std::vector<std::uint32_t>>& blocks) {
    for (auto& block : blocks) {
        for (std::uint32_t i = 16; i < 64; ++i) {
            std::uint32_t s0 = small_sigma0(block[i - 15]);
            std::uint32_t s1 = small_sigma1(block[i - 2]);
            block.push_back((block[i - 16] + s0 + block[i - 7] + s1) & 0xFFFFFFFF);
        }
    }
}

// Compression Function for each block
void Compression(std::vector<std::uint32_t>& H, const std::vector<std::uint32_t>& K, std::vector<std::vector<std::uint32_t>>& blocks) {
    for (const auto& block : blocks) {
        std::uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
        std::uint32_t e = H[4], f = H[5], g = H[6], h = H[7];

        for (std::uint32_t i = 0; i < 64; ++i) {
            std::uint32_t T1 = h + big_sigma1(e) + choice(e, f, g) + K[i] + block[i];
            std::uint32_t T2 = big_sigma0(a) + majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = (d + T1) & 0xFFFFFFFF;
            d = c;
            c = b;
            b = a;
            a = (T1 + T2) & 0xFFFFFFFF;
        }

        // Update the hash values with modulo 2^32
        H[0] = (H[0] + a) & 0xFFFFFFFF;
        H[1] = (H[1] + b) & 0xFFFFFFFF;
        H[2] = (H[2] + c) & 0xFFFFFFFF;
        H[3] = (H[3] + d) & 0xFFFFFFFF;
        H[4] = (H[4] + e) & 0xFFFFFFFF;
        H[5] = (H[5] + f) & 0xFFFFFFFF;
        H[6] = (H[6] + g) & 0xFFFFFFFF;
        H[7] = (H[7] + h) & 0xFFFFFFFF;
    }
}

// SHA-256 Function
std::string SHA256(const std::string& input) {
    std::vector<std::uint32_t> H = InitializeHashValues();
    std::vector<std::uint32_t> K = InitializeConstants();
    auto padded_message = Padding(input);
    auto blocks = SegmentToBlocks(padded_message);
    MessageSchedule(blocks);
    Compression(H, K, blocks);

    // Convert final hash values to hex string
    std::string hash;
    for (auto h : H) {
        char buffer[9];
        snprintf(buffer, sizeof(buffer), "%08x", h);
        hash += buffer;
    }
    return hash;
}

int main() {
    std::string input = "abc";
    std::cin>>input;
    std::string hash = SHA256(input);
    std::cout << "SHA-256 hash of \"" << input << "\": " << hash << std::endl;
    return 0;
}
