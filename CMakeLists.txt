cmake_minimum_required( VERSION 3.21.0 FATAL_ERROR )
project(l3tx VERSION 0.1 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)

# YouCompleteMe
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -Wall -Werror -march=native -g -m64 -ffast-math -fdiagnostics-color")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -Wall -Werror -march=native -m64 -ffast-math -fdiagnostics-color")

# Intel Paillier Cryto Library
find_package(IPCL 2.0.0
	HINTS ${IPCL_HINT_DIR}
	REQUIRED
)

set (L3TX_SRC
 	main.cpp
        bench.cpp
        l3tx.cpp
)

add_executable(l3tx ${L3TX_SRC})

target_include_directories(l3tx PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
	${IPCL_INC_DIR}
)

target_link_libraries(l3tx IPCL::ipcl secp256k1 crypto)
