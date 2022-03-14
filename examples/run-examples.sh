#!/usr/bin/env bash

# This script is intended to be run on a virtual machine with no key in the keychain
# If you would like to try on a normal user account, make sure that identity /consumerPrefix1, /aaPrefix, /producerPrefix
# are not used, as these keys will be deleted.

if ndnsec list | grep "/consumerPrefix1\|/aaPrefix\|/producerPrefix"
then
  echo "Make sure you so not have identity /consumerPrefix1, /aaPrefix, /producerPrefix in the keychain before try again"
  exit 1
fi

export NDN_LOG=*=INFO

ndnsec key-gen -t r /consumerPrefix1
ndnsec key-gen /aaPrefix
ndnsec key-gen /producerPrefix

$1/examples/kp-aa-example &
sleep 1
$1/examples/kp-producer-example &
sleep 1

$1/examples/kp-consumer-example | grep "Hello world"
exit_val=$?

kill %1
kill %2

ndnsec delete /consumerPrefix1
ndnsec delete /aaPrefix
ndnsec delete /producerPrefix

exit $exit_val
