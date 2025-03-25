#include "defines.h"

#include <errno.h>
#include <error.h>

const char *zt_error_str(error_t err) {
  switch (err) {
  case ERR_SUCCESS:
    return "success";
  case ERR_NULL_PTR:
    return "null pointer argument(s)";
  case ERR_BAD_ARGS:
    return "invalid argument(s)";
  case ERR_MEM_FAIL:
    return "out of memory";
  case ERR_NOT_INIT:
    return "not initialized";
  case ERR_NOT_ALLOC:
    return "memory/interface not allocated";
  case ERR_INTERNAL:
    return "internal library failure";
  case ERR_BUFFER_TOO_SMALL:
    return "buffer too small";
  case ERR_REQUEST_TOO_LARGE:
    return "request exceeded maximum allowed size";
  case ERR_NOT_SUPPORTED:
    return "operation not supported";
  case ERR_INVALID:
    return "invalid operation sequence";
  case ERR_INVALID_DATUM:
    return "mismatch from expected data";
  case ERR_AUTH_FAIL:
    return "authentication failure";
  case ERR_AGAIN:
    return "try again";
  case ERR_TIMEOUT:
    return "operation timed out";
  case ERR_NORESOLVE:
    return "could not resolve host";
  case ERR_TCP_CONNECT:
    return "TCP connection failed";
  case ERR_TCP_SEND:
    return "TCP send failed";
  case ERR_TCP_RECV:
    return "TCP receive failed";
  case ERR_ALREADY:
    return "already in progress";
  default:
    return "unknown error";
  }
}
