#include "l3tx.hpp"
#include "helpers.hpp"
#include <assert.h>
#include <cstring>
#include <ipcl/plaintext.hpp>
#include <ipcl/pri_key.hpp>
#include <ipcl/pub_key.hpp>
#include <string.h>

namespace {
// Hello World! sha-256
constexpr unsigned char msg_hash[32] = {
    0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4, 0x3B, 0x8A, 0xC0,
    0x06, 0x4E, 0x4A, 0x01, 0x64, 0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8,
    0x69, 0x34, 0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
};

bool check_signature(EVP_MD_CTX *ssl, const secp256k1_context *ctx,
                     const unsigned char *signature, int id,
                     const unsigned char *msg, const unsigned char *expected) {

  secp256k1_ecdsa_recoverable_signature sig;
  secp256k1_pubkey pubkey;

  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, signature,
                                                           id)) {
    return false;
  }
  if (!secp256k1_ecdsa_recover(ctx, &pubkey, &sig, msg)) {
    return false;
  }
  size_t output_len = 65;
  unsigned char pubkey_out[65];
  secp256k1_ec_pubkey_serialize(ctx, pubkey_out, &output_len, &pubkey,
                                SECP256K1_EC_UNCOMPRESSED);

  EVP_DigestInit_ex(ssl, EVP_sha3_256(), NULL);
  EVP_DigestUpdate(ssl, pubkey_out + 1, 64);
  unsigned char hashed_pubkey[32];
  EVP_DigestFinal(ssl, hashed_pubkey, NULL);

  return !memcmp(hashed_pubkey + 12, expected, 20);
};

}; // namespace
namespace l3tx {
bool is_transaction_signature_valid(EVP_MD_CTX *ssl,
                                    const secp256k1_context *ctx,
                                    const state_t &state,
                                    const signed_transaction_t &signed_tx) {

  auto sender = state.accounts[signed_tx.message.from];
  return check_signature(
      ssl, ctx, signed_tx.signature.data(), signed_tx.signature[64],
      reinterpret_cast<const unsigned char *>(&signed_tx.message),
      sender.address.data());
};

bool is_encrypted_transaction_signature_valid(
    EVP_MD_CTX *ssl, const secp256k1_context *ctx,
    const encrypted_state_t &state,
    const signed_encrypted_transaction_t &signed_tx) {

  auto sender = state.accounts[signed_tx.message.from];
  unsigned char hash[32];
  signed_tx.message.hash(ssl, hash);
  return check_signature(ssl, ctx, signed_tx.signature.data(),
                         signed_tx.signature[64], hash, sender.address.data());
};

create_message_t::create_message_t(EVP_MD_CTX *ssl,
                                   const secp256k1_context *ctx,
                                   const unsigned char *seckey) {
  secp256k1_pubkey pubkey;
  /* Public key creation using a valid context with a verified secret key
   * should never fail */
  auto return_val = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
  assert(return_val);

  /* Serialize the pubkey in uncompressed form(65 bytes). Should always
   * return 1. */
  unsigned char uncompressed_pubkey[65];
  auto len = sizeof(uncompressed_pubkey);
  return_val = secp256k1_ec_pubkey_serialize(
      ctx, uncompressed_pubkey, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
  assert(return_val);
  /* Should be the same size as the size of the output, because we passed a 65
   * byte array. */
  assert(len == sizeof(uncompressed_pubkey));

  EVP_DigestInit_ex(ssl, EVP_sha3_256(), NULL);
  EVP_DigestUpdate(ssl, uncompressed_pubkey + 1, 64);
  unsigned char hashed_pubkey[32];
  EVP_DigestFinal(ssl, hashed_pubkey, NULL);
  std::copy(hashed_pubkey + 12, hashed_pubkey + 32, address.begin());

  secp256k1_ecdsa_recoverable_signature sig;
  return_val =
      secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg_hash, seckey, NULL, NULL);
  assert(return_val);

  int id;
  secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, signature.data(),
                                                          &id, &sig);
  signature[64] = id;
};

signed_transaction_t::signed_transaction_t(const secp256k1_context *ctx,
                                           const unsigned char *seckey,
                                           transaction_t &&tx) noexcept
    : message{std::move(tx)} {
  secp256k1_ecdsa_recoverable_signature sig;
  auto return_val = secp256k1_ecdsa_sign_recoverable(
      ctx, &sig, reinterpret_cast<const unsigned char *>(&message.from), seckey,
      NULL, NULL);
  assert(return_val);

  int id;
  secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, signature.data(),
                                                          &id, &sig);
  signature[64] = id;
};

bool process_create_message(EVP_MD_CTX *ssl, const secp256k1_context *ctx,
                            state_t &state, const create_message_t &msg) {
  if (!check_signature(ssl, ctx, msg.signature.data(), msg.signature[64],
                       msg_hash, msg.address.data())) {
    return false;
  }
  state.accounts.emplace_back(account_t{msg.address});
  return true;
};

encrypted_account_t::encrypted_account_t(
    const ipcl::PublicKey &key,
    const std::array<unsigned char, 20> &address) noexcept
    : address{address}, balance{key, uint32_t{}} {}

bool process_encrypted_create_message(EVP_MD_CTX *ssl,
                                      const secp256k1_context *ctx,
                                      const ipcl::PublicKey &key,
                                      encrypted_state_t &state,
                                      const create_message_t &msg) {
  if (!check_signature(ssl, ctx, msg.signature.data(), msg.signature[64],
                       msg_hash, msg.address.data())) {
    return false;
  }
  state.accounts.emplace_back(encrypted_account_t{key, msg.address});
  return true;
}

bool process_transaction(EVP_MD_CTX *ssl, const secp256k1_context *ctx,
                         state_t &state,
                         const signed_transaction_t &signed_tx) {
  auto tx = signed_tx.message;
  if (tx.from >= state.accounts.size() || tx.to >= state.accounts.size())
    return false;
  auto &sender = state.accounts[tx.from];
  if (tx.amount > sender.balance)
    return false;
  if (tx.nonce != sender.nonce + 1)
    return false;

  // Verify signature;
  if (!is_transaction_signature_valid(ssl, ctx, state, signed_tx)) {
    return false;
  }
  sender.nonce++;
  sender.balance -= tx.amount;
  auto &receiver = state.accounts[tx.to];
  receiver.balance += tx.amount;
  state.transactions.emplace_back(signed_tx.message);
  return true;
}

bool validate_encrypted_transaction_balances(
    EVP_MD_CTX *ssl, const secp256k1_context *ctx, encrypted_state_t &state,
    const ipcl::PrivateKey &privkey, const encrypted_transaction_t &tx) {
  auto decripted_amount = privkey.decrypt(tx.amount);
  std::vector<uint32_t> amount_vec{decripted_amount};
  assert(amount_vec.size() <= 2);
  if (amount_vec.size() < 2) {
    printf("Vec less than 2, %u\n", amount_vec[0]);
  } else {
    printf("vec is higher than 2 %u:%u\n", amount_vec[0], amount_vec[1]);
  }

  auto sender = state.accounts[tx.from];
  auto decripted_balance = privkey.decrypt(sender.balance);
  std::vector<uint32_t> balance_vec{decripted_balance};
  assert(balance_vec.size() <= 2);
  if (balance_vec.size() < 2) {
    printf("balance vec less than 2, %u\n", balance_vec[0]);
  } else {
    printf("balance vec is higher than 2 %u:%u\n", balance_vec[0],
           balance_vec[1]);
  }

  if (amount_vec.size() == balance_vec.size()) {
    return !std::lexicographical_compare(
        balance_vec.rbegin(), balance_vec.rend(), amount_vec.rbegin(),
        amount_vec.rend());
  }
  if (amount_vec.size() < balance_vec.size()) {
    return true;
  }
  return false;
}

bool process_encrypted_transaction(
    EVP_MD_CTX *ssl, const secp256k1_context *ctx, encrypted_state_t &state,
    const signed_encrypted_transaction_t &signed_tx) {
  auto tx = signed_tx.message;
  if (tx.from >= state.accounts.size() || tx.to >= state.accounts.size())
    return false;
  auto &sender = state.accounts[tx.from];
  if (tx.nonce != sender.nonce + 1)
    return false;

  // Verify signature;
  if (!is_encrypted_transaction_signature_valid(ssl, ctx, state, signed_tx)) {
    return false;
  }
  sender.nonce++;
  ipcl::PlainText minus_one(-1);
  auto minus_amount = tx.amount * minus_one;
  sender.balance = sender.balance + minus_amount;
  auto &receiver = state.accounts[tx.to];
  receiver.balance = receiver.balance + tx.amount;
  state.transactions.emplace_back(signed_tx.message);
  return true;
}

encrypted_transaction_t::encrypted_transaction_t(
    const transaction_t &tx, const ipcl::PublicKey &key) noexcept
    : from{tx.from}, to{tx.to}, nonce{tx.nonce},
      amount{key, helpers::uint64_to_vector(tx.amount)} {};

void encrypted_transaction_t::hash(EVP_MD_CTX *ssl,
                                   unsigned char *digest) const noexcept {
  EVP_DigestInit_ex(ssl, EVP_sha3_256(), NULL);
  EVP_DigestUpdate(ssl, &from, 24); // hash from, to, nonce
  std::ostringstream os;
  ipcl::serializer::serialize(os, amount);
  auto serialized = os.str();
  EVP_DigestUpdate(ssl, serialized.data(), serialized.size());
  EVP_DigestFinal(ssl, digest, NULL);
};

signed_encrypted_transaction_t::signed_encrypted_transaction_t(
    EVP_MD_CTX *ssl, const secp256k1_context *ctx, const unsigned char *seckey,
    encrypted_transaction_t &&tx) noexcept
    : message{std::move(tx)} {
  secp256k1_ecdsa_recoverable_signature sig;
  unsigned char tx_hash[32];
  tx.hash(ssl, tx_hash);
  auto return_val =
      secp256k1_ecdsa_sign_recoverable(ctx, &sig, tx_hash, seckey, NULL, NULL);
  assert(return_val);

  int id;
  secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, signature.data(),
                                                          &id, &sig);
  signature[64] = id;
};

}; // namespace l3tx
