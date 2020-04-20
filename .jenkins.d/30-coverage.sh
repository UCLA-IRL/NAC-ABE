#!/usr/bin/env bash
set -ex

if [[ $JOB_NAME == *"code-coverage" ]]; then
    gcovr --object-directory=build \
          --output=build/coverage.xml \
          --exclude="$PWD/tests" \
          --root=. \
          --xml

    # Generate also a detailed HTML output, but using lcov (better results)
    lcov --quiet \
         --capture \
         --directory . \
         --no-external \
         --rc lcov_branch_coverage=1 \
         --output-file build/coverage-with-tests.info

    lcov --quiet \
         --remove build/coverage-with-tests.info "$PWD/tests/*" \
         --rc lcov_branch_coverage=1 \
         --output-file build/coverage.info

    genhtml --branch-coverage \
            --demangle-cpp \
            --frames \
            --legend \
            --output-directory build/coverage \
            --title "ndncert unit tests" \
            build/coverage.info
fi
