#include "helpers.hpp"

namespace helpers{
std::vector<uint32_t> uint64_to_vector(uint64_t value) {
  std::vector<uint32_t> res;

  uint32_t lowerPart = static_cast<uint32_t>(value);
  uint32_t upperPart = static_cast<uint32_t>(value >> 32);

  // Push the parts into the vector
  res.push_back(lowerPart);
  res.push_back(upperPart);

  return res;
};
}; // namespace helpers
