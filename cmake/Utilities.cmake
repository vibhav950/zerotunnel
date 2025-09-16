# Utility functions for CMake scripts

# Count the number of true values in a list of boolean variables.
# Usage: zt_count_true(<output_variable> <var1> <var2> ...)
function(zt_count_true _output_count)
  set(_len_val 0)
  foreach(_opt_var IN LISTS ARGN)
    if(${_opt_var})
      math(EXPR _len_val "${_len_val} + 1")
    endif()
  endforeach()
  set(${_output_count} ${_len_val} PARENT_SCOPE)
endfunction()

# Find all HAVE_* variables that are true.
# Usage: zt_parse_feature_macros(<output_macro_list> HAVE_FOO HAVE_BAR ...)
function(zt_parse_feature_macros _output_macro_list)
  set(_macro_list "")
  foreach(_var IN LISTS ARGN)
    if(_var MATCHES "^HAVE_")
      if(${_var})
        list(APPEND _macro_list ${_var})
      endif()
    endif()
  endforeach()
  set(${_output_macro_list} ${_macro_list} PARENT_SCOPE)
endfunction()