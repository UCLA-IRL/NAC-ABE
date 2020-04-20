#!/usr/bin/env bash
set -ex

# Prepare environment
rm -rf ~/.ndn

BOOST_VERSION=$(python3 -c "import sys; sys.path.append('build/c4che'); import _cache; print(_cache.BOOST_VERSION_NUMBER);")

ut_log_args() {
    if (( BOOST_VERSION >= 106200 )); then
        echo --logger=HRF,test_suite,stdout:XML,all,build/xunit-${1:-report}.xml
    else
        if [[ -n $XUNIT ]]; then
            echo --log_level=all $( (( BOOST_VERSION >= 106000 )) && echo -- ) \
                 --log_format2=XML --log_sink2=build/xunit-${1:-report}.xml
        else
            echo --log_level=test_suite
        fi
    fi
}

# https://github.com/google/sanitizers/wiki/AddressSanitizerFlags
ASAN_OPTIONS="color=always"
ASAN_OPTIONS+=":check_initialization_order=1"
ASAN_OPTIONS+=":detect_stack_use_after_return=1"
ASAN_OPTIONS+=":strict_init_order=1"
ASAN_OPTIONS+=":strict_string_checks=1"
ASAN_OPTIONS+=":detect_invalid_pointer_pairs=2"
ASAN_OPTIONS+=":strip_path_prefix=${PWD}/"
export ASAN_OPTIONS

export BOOST_TEST_BUILD_INFO=1
export BOOST_TEST_COLOR_OUTPUT=1

# Run unit tests
./build/unit-tests $(ut_log_args)
