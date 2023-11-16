#include "bench.hpp"
#include <ipcl/ipcl.hpp>
#include <ipcl/utils/context.hpp>

int main() {
#ifdef IPCL_USE_QAT
  ipcl::initializeContext("QAT");

  if (ipcl::isQATActive())
    std::cout << "QAT Context: ACTIVE" << std::endl;
  else
    std::cout << "QAT Context: INACTIVE." << std::endl;

  if (ipcl::isQATRunning())
    std::cout << "QAT Instances: RUNNING" << std::endl;
  else
    std::cout << "QAT Instances: NOT RUNNING." << std::endl;
#else
  std::cout << "Running without QAT" << std::endl;
  ipcl::initializeContext("default");
#endif // IPCL_USE_QAT
  auto status = l3tx::bench();

  ipcl::terminateContext();

#ifdef IPCL_USE_QAT
                    if (!ipcl::isQATActive()) std::cout
                << "QAT Context: INACTIVE" << std::endl;
  else std::cout << "QAT Context: ACTIVE." << std::endl;
  if (!ipcl::isQATRunning())
    std::cout << "QAT Instances: NOT RUNNING" << std::endl;
  else
    std::cout << "QAT Instances: STILL RUNNING." << std::endl;
#endif

  return status;
}
