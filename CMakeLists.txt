cmake_minimum_required(VERSION 3.10)
project(zerotunnel VERSION 0.1.0 LANGUAGES C)

set(HANDSHAKE_PROTOCOL_VERSION 1)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_MINIMAL_GCC_VERSION "7.1.0")

include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckLibraryExists)
find_package(PkgConfig)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/")
include(Utilities)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
  set(ARCH "x86_64")
  set(ARCH_X64 ON)
else()
  message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(SYS_LINUX TRUE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(SYS_WIN32 TRUE)
else()
  message(FATAL_ERROR "Unsupported operating system: ${CMAKE_SYSTEM_NAME}")
endif()

set(PLATFORM_LIBRARIES "")

option(WITH_OPENSSL "Build with OpenSSL support" ON)
option(WITH_GNUTLS "Build with GnuTLS support" OFF)

zt_count_true(_crypto_backends_enabled
  WITH_OPENSSL
  WITH_GNUTLS
)
if(NOT(_crypto_backends_enabled EQUAL 1))
  message(FATAL_ERROR "Exactly one crypto backend must be enabled.")
endif()

include_directories(
  ${PROJECT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}/lib
)

if(NOT SYS_WIN32)
  set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
  set(THREADS_PREFER_PTHREAD_FLAG TRUE)
endif()

find_package(Threads REQUIRED)
find_package(SQLite3)

set(HAVE_SQLITE3 ${SQLite3_FOUND})

find_library(BSD_LIBRARY NAMES bsd)
if (BSD_LIBRARY)
  list(APPEND PLATFORM_LIBRARIES ${BSD_LIBRARY})
endif()

find_library(SYSTEMD_LIBRARY NAMES systemd)
if (SYSTEMD_LIBRARY)
  list(APPEND PLATFORM_LIBRARIES ${SYSTEMD_LIBRARY})
endif()

find_path(LIBGCRYPT_INCLUDE_DIR NAMES gcrypt.h)
find_library(LIBGCRYPT_LIBRARY NAMES gcrypt libgcrypt)
if(LIBGCRYPT_INCLUDE_DIR AND LIBGCRYPT_LIBRARY)
  include_directories(${LIBGCRYPT_INCLUDE_DIR})
  list(APPEND PLATFORM_LIBRARIES ${LIBGCRYPT_LIBRARY})
  add_compile_definitions(HAVE_LIBGCRYPT)
endif()

if(NOT SYS_WIN32)
check_include_files(sys/random.h HAVE_SYS_RANDOM_H)
if(HAVE_SYS_RANDOM_H)
  set(CMAKE_EXTRA_INCLUDE_FILES sys/random.h)
  check_function_exists(getentropy HAVE_GETENTROPY)
  set(CMAKE_EXTRA_INCLUDE_FILES)
endif()

check_include_files(linux/random.h HAVE_LINUX_RANDOM_H)
if(HAVE_LINUX_RANDOM_H)
  set(CMAKE_EXTRA_INCLUDE_FILES linux/random.h)
  check_function_exists(getrandom HAVE_GETRANDOM)
  set(CMAKE_EXTRA_INCLUDE_FILES)
endif()

check_include_files(sys/epoll.h HAVE_SYS_EPOLL_H)
if(HAVE_SYS_EPOLL_H)
  check_function_exists(epoll_create1 HAVE_EPOLL)
endif()

check_include_files(fcntl.h HAVE_FCNTL_H)
if(HAVE_FCNTL_H)
  check_function_exists(fcntl HAVE_FCNTL)
  check_function_exists(posix_fallocate HAVE_POSIX_FALLOCATE)
  check_function_exists(fallocate HAVE_FALLOCATE)
endif()
endif() # NOT SYS_WIN32

if(SYS_WIN32)
  set(HAVE_IPV6 1)
elseif(SYS_LINUX)
  check_c_source_compiles("
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>

    int main() {
      struct sockaddr_in6 s; struct in6_addr t=in6addr_any; int i=AF_INET6; s; t.s6_addr[0] = 0;
      return 0;
    }" HAVE_IPV6)
endif()

set(CRYPTO_INCLUDE_DIRS "")
set(CRYPTO_LIBRARIES "")

if(WITH_OPENSSL)
  find_package(OpenSSL REQUIRED)

  if(OPENSSL_VERSION VERSION_LESS "3.5")
    message(FATAL_ERROR "OpenSSL version ${OPENSSL_VERSION} is less than the required version 3.5")
  endif()

  list(APPEND CRYPTO_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
  list(APPEND CRYPTO_LIBRARIES OpenSSL::Crypto)
  add_compile_definitions(OPENSSL)
elseif(WITH_GNUTLS)
  find_package(GnuTLS REQUIRED)

  if(GNUTLS_VERSION VERSION_LESS "3.8.9")
    message(FATAL_ERROR "GnuTLS version ${GNUTLS_VERSION} is less than the required version 3.6")
  endif()

  list(APPEND CRYPTO_INCLUDE_DIRS ${GNUTLS_INCLUDE_DIR})
  list(APPEND CRYPTO_LIBRARIES GnuTLS::gnutls)
  add_compile_definitions(GNUTLS)
endif()

file(GLOB_RECURSE C_SOURCES
  "common/*.c"
  "lib/*.c"
  "random/*.c"
  "src/*.c"
)

file(GLOB CRYPTO_SOURCES
  "crypto/cipher.c"
  "crypto/hmac.c"
  "crypto/kdf.c"
  "crypto/kem.c"
  "crypto/kex.c"
)

if(WITH_OPENSSL)
  file(GLOB_RECURSE CRYPTO_BACKEND_SOURCES "crypto/*_ossl.c")
elseif(WITH_GNUTLS)
  file(GLOB_RECURSE CRYPTO_BACKEND_SOURCES "crypto/*_gtls.c")
endif()

set(ALL_SOURCES ${C_SOURCES} ${CRYPTO_SOURCES} ${CRYPTO_BACKEND_SOURCES})

file(GLOB_RECURSE TEST_FILES "tests/*.c")
list(REMOVE_ITEM ALL_SOURCES ${TEST_FILES})

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/protocol.in.h
  ${CMAKE_CURRENT_BINARY_DIR}/lib/protocol.h
  @ONLY
)

add_executable(zerotunnel
  ${ALL_SOURCES}
)

zt_parse_feature_macros(_feature_macros_list
  HAVE_SQLITE3
  HAVE_LIBGCRYPT
  HAVE_GETENTROPY
  HAVE_GETRANDOM
  HAVE_EPOLL
  HAVE_FCNTL
  HAVE_POSIX_FALLOCATE
  HAVE_POSIX_FADVISE
  HAVE_IPV6
)
add_compile_definitions(${_feature_macros_list})

target_link_libraries(zerotunnel PRIVATE
  ${CRYPTO_LIBRARIES}
  ${PLATFORM_LIBRARIES}
  Threads::Threads
  SQLite::SQLite3
)

install(TARGETS zerotunnel DESTINATION bin)

# add_subdirectory(tests)
