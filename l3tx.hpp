#pragma once

#include <array>
#include <bits/iterator_concepts.h>
#include <cstdint>
#include <ipcl/ciphertext.hpp>
#include <ipcl/pub_key.hpp>
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
  uint64_t nonce;
  ipcl::CipherText balance;
  encrypted_account_t(const ipcl::PublicKey &,
                      const std::array<unsigned char, 20> &) noexcept;
  encrypted_account_t(const std::array<unsigned char, 20> &address,
                      uint64_t nonce, const ipcl::CipherText &balance) noexcept
      : address{address}, nonce{nonce}, balance{balance} {};
};

struct transaction_t {
  uint64_t from, to, amount, nonce;
};

struct encrypted_transaction_t {
  uint64_t from, to, nonce;
  ipcl::CipherText amount;
  encrypted_transaction_t(const transaction_t &tx,
                          const ipcl::PublicKey &key) noexcept;
  void hash(EVP_MD_CTX *ssl, unsigned char *digest) const noexcept;
};

struct signed_transaction_t {
  transaction_t message;
  std::array<unsigned char, 65> signature;
  signed_transaction_t(const secp256k1_context *, const unsigned char *,
                       transaction_t &&) noexcept;
};

struct signed_encrypted_transaction_t {
  encrypted_transaction_t message;
  std::array<unsigned char, 65> signature;
  signed_encrypted_transaction_t(EVP_MD_CTX *, const secp256k1_context *,
                                 const unsigned char *,
                                 encrypted_transaction_t &&) noexcept;
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

bool process_encrypted_create_message(EVP_MD_CTX *, const secp256k1_context *,
                                      const ipcl::PublicKey &,
                                      encrypted_state_t &,
                                      const create_message_t &);

bool process_transaction(EVP_MD_CTX *, const secp256k1_context *, state_t &,
                         const signed_transaction_t &);

bool validate_encrypted_transaction_balances(EVP_MD_CTX *,
                                             const secp256k1_context *,
                                             encrypted_state_t &,
                                             const ipcl::PrivateKey &,
                                             const encrypted_transaction_t &);

bool process_encrypted_transaction(EVP_MD_CTX *, const secp256k1_context *,
                                   encrypted_state_t &,
                                   const signed_encrypted_transaction_t &);
} // namespace l3tx
