#!/usr/bin/env bash
set -ex

git submodule sync
git submodule update --init

if [[ -z $DISABLE_ASAN ]]; then
    ASAN="--with-sanitizer=address"
fi
if [[ $JOB_NAME == *"code-coverage" ]]; then
    COVERAGE="--with-coverage"
fi

if [[ $JOB_NAME != *"code-coverage" && $JOB_NAME != *"limited-build" ]]; then
    # Build in release mode with tests
    ./waf --color=yes configure --with-tests
    ./waf --color=yes build -j$WAF_JOBS

    # Cleanup
    ./waf --color=yes distclean

    # Build in release mode without tests
    ./waf --color=yes configure
    ./waf --color=yes build -j$WAF_JOBS

    # Cleanup
    ./waf --color=yes distclean
fi

# Build in debug mode with tests
./waf --color=yes configure --debug --with-tests $ASAN $COVERAGE
./waf --color=yes build -j$WAF_JOBS

# (tests will be run against the debug version)

# Install
sudo_preserve_env PATH -- ./waf --color=yes install

if has Linux $NODE_LABELS; then
    sudo ldconfig
fi
