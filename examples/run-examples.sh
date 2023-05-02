#!/usr/bin/env bash

# This script is intended to be run on a virtual machine with no key in the keychain
# If you would like to try on a normal user account, make sure that identity /consumerPrefix1, /aaPrefix, /producerPrefix
# are not used, as these keys will be deleted.

if ndnsec list | grep "/example/consumer\|/example/aa\|/example/producer"
then
  echo "cleaning example identities"
  ndnsec delete /example/consumer
  ndnsec delete /example/aa
  ndnsec delete /example/producer
fi

export NDN_LOG=*=INFO

ndnsec key-gen /example > /dev/null
ndnsec cert-dump -i /example > example-trust-anchor.cert

ndnsec key-gen /example/aa > /dev/null
ndnsec sign-req /example/aa | ndnsec cert-gen -s /example -i example | ndnsec cert-install -

ndnsec key-gen /example/producer > /dev/null
ndnsec sign-req /example/producer | ndnsec cert-gen -s /example -i example | ndnsec cert-install -

ndnsec key-gen -t r /example/consumer > /dev/null
ndnsec sign-req /example/consumer | ndnsec cert-gen -s /example -i example | ndnsec cert-install -

$1/examples/kp-aa-example &
aa_pid=$!
sleep 1
$1/examples/kp-producer-example &
pro_pid=$!
sleep 1

$1/examples/kp-consumer-example | grep "Hello world"
exit_val=$?

kill $aa_pid
kill $pro_pid

ndnsec delete /example/consumer
ndnsec delete /example/aa
ndnsec delete /example/producer

exit $exit_val
