#include "bench.hpp"
#include "l3tx.hpp"
#include <algorithm>
#include <assert.h>
#include <chrono>
#include <iostream>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/pub_key.hpp>
#include <random>
#include <secp256k1.h>
#include <sys/random.h>

using Seckey = std::array<unsigned char, 32>;

namespace {
constexpr uint64_t operator_balance = 100'000'000'000'000ULL;
constexpr uint64_t account_starting_balance = 10'000'000ULL;
constexpr uint64_t max_transaction_amount = 10'000ULL;
constexpr auto num = 1'000'000u;

static int fill_random(unsigned char *data, size_t size) {
  size_t res = getrandom(data, size, 0);
  if (res < 0 || (size_t)res != size) {
    return 0;
  } else {
    return 1;
  }
  return 0;
}

void fill_in_accounts(EVP_MD_CTX *ssl, const secp256k1_context *ctx,
                      l3tx::state_t &state, std::vector<Seckey> &keys,
                      size_t num) {
  for (size_t i = 0; i < num; i++) {
    // Key Generation
    Seckey seckey;
    while (1) {
      if (!fill_random(seckey.data(), sizeof(seckey))) {
        printf("Failed to generate randomness\n");
        return;
      }
      if (secp256k1_ec_seckey_verify(ctx, seckey.data())) {
        break;
      }
    }
    keys.emplace_back(seckey);
    // Create the message to create the account
    auto msg = l3tx::create_message_t(ssl, ctx, seckey.data());
    assert(l3tx::process_create_message(ssl, ctx, state, msg));
  }
};

void fund_accounts(EVP_MD_CTX *ssl, const secp256k1_context *ctx,
                   l3tx::state_t &state, const Seckey &key) {
  auto &sequencer = state.accounts[0];
  sequencer.balance = operator_balance;
  for (uint64_t i = 1; i < state.accounts.size(); i++) {
    l3tx::signed_transaction_t tx{
        ctx, key.data(),
        l3tx::transaction_t{0, i, account_starting_balance, i}};
    assert(l3tx::process_transaction(ssl, ctx, state, tx));
  }
}

void send_random_tx(EVP_MD_CTX *ssl, const secp256k1_context *ctx,
                    l3tx::state_t &state, const std::vector<Seckey> &keys,
                    uint64_t num) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint64_t> distribution(0,
                                                       max_transaction_amount);
  std::uniform_int_distribution<size_t> user(0, state.accounts.size() - 1);

  for (uint64_t i = 0; i < num; i++) {
    size_t from = user(gen);
    auto &sender = state.accounts[from];
    size_t to = user(gen);
    uint64_t amount = distribution(gen);
    if (amount > sender.balance) {
      amount = sender.balance;
    }
    l3tx::signed_transaction_t tx{
        ctx, keys[from].data(),
        l3tx::transaction_t{from, to, amount, sender.nonce + 1}};
    assert(l3tx::process_transaction(ssl, ctx, state, tx));
  }
}

void report_state_size(const l3tx::state_t &state) {
  std::cout << "Size of the state: "
            << state.accounts.size() * sizeof(l3tx::account_t) +
                   state.transactions.size() * sizeof(l3tx::transaction_t)
            << " Bytes." << std::endl;
}
} // namespace

namespace l3tx {
int bench() noexcept {
  auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  unsigned char randomize[32];
  if (!fill_random(randomize, sizeof(randomize))) {
    printf("Failed to generate randomness\n");
    return 1;
  }
  /* Randomizing the context is recommended to protect against side-channel
   * leakage See `secp256k1_context_randomize` in secp256k1.h for more
   * information about it. This should never fail. */
  auto return_val = secp256k1_context_randomize(ctx, randomize);
  assert(return_val);

  // Generate the accounts
  l3tx::state_t state{};
  auto ssl = EVP_MD_CTX_new();

  printf("Generating %d accounts.\n", num);
  std::vector<Seckey> keys{};
  keys.reserve(num);
  auto start_time = std::chrono::steady_clock::now();
  fill_in_accounts(ssl, ctx, state, keys, num);
  auto step = std::chrono::steady_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::microseconds>(step - start_time);
  std::cout << "Generated @" << duration.count() / num
            << " microseconds per account" << std::endl;
  report_state_size(state);
  assert(keys.size() == num);

  // Fund them with the first account
  printf("\nFunding accounts.\n");
  start_time = step;
  fund_accounts(ssl, ctx, state, keys[0]);
  step = std::chrono::steady_clock::now();
  duration =
      std::chrono::duration_cast<std::chrono::microseconds>(step - start_time);
  std::cout << "Performed @" << duration.count() / (num - 1)
            << " microseconds per transaction" << std::endl;
  report_state_size(state);

  // Submit random transactions
  printf("\nSending %d random transactions.\n", num);
  start_time = step;
  send_random_tx(ssl, ctx, state, keys, num);
  step = std::chrono::steady_clock::now();
  duration =
      std::chrono::duration_cast<std::chrono::microseconds>(step - start_time);
  std::cout << "Performed @" << duration.count() / (num - 1)
            << " microseconds per transaction" << std::endl;
  report_state_size(state);

  // Generate Paillier keys
  printf("\nGenerating Private key for Paillier encryption.\n");
  ipcl::KeyPair ipcl_key = ipcl::generateKeypair(2048, true);

  printf("\nFunding %d accounts.\n", num);
  state.transactions.clear();
  start_time = step;
  /* fund_encrypted_accounts(ssl, ctx, state, encrypted_state, ipcl_key.pub_key,
                          keys[0]);
    */

  EVP_MD_CTX_free(ssl);
  return 0;
}
} // namespace l3tx
