#pragma once

#include <array>
#include <cstdint>
#include <ipcl/ciphertext.hpp>
#include <openssl/evp.h>
#include <secp256k1_recovery.h>
#include <vector>

namespace l3tx{
struct account_t {
  std::array<unsigned char, 20> address;
  uint64_t nonce, balance;
};

struct encrypted_account_t {
  std::array<unsigned char, 20> address;
  ipcl::CipherText nonce, balance;
};

struct transaction_t {
  uint64_t from, to, amount, nonce;
};

struct encrypted_transaction_t {
  uint64_t from, to;
  ipcl::CipherText nonce, balance;
};

struct signed_transaction_t {
  transaction_t message;
  std::array<unsigned char, 65> signature;
  signed_transaction_t(const secp256k1_context *, const unsigned char *,
                       transaction_t &&) noexcept;
};

struct create_message_t {
  std::array<unsigned char, 20> address;
  std::array<unsigned char, 65> signature;
  create_message_t(EVP_MD_CTX *ssl, const secp256k1_context *ctx,
                   const unsigned char *seckey);
};

struct state_t {
  std::vector<account_t> accounts;
  std::vector<transaction_t> transactions;
};

struct encrypted_state_t {
  std::vector<encrypted_account_t> accounts;
  std::vector<encrypted_transaction_t> transactions;
};

bool process_create_message(EVP_MD_CTX *, const secp256k1_context *, state_t &,
                            const create_message_t &);

bool process_transaction(EVP_MD_CTX *, const secp256k1_context *, state_t &,
                         const signed_transaction_t &);
} // namespace l3tx
