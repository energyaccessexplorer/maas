#!/usr/bin/env bash

# This is just a small utility for testing mås

# export TOKEN_FILE=
# export SERVER=
# export AUTH_URL=

# export USER_EMAIL=
# export USER_PASS=

# export HTTP_USER=
# export HTTP_PASS=

# export SNATCH_LOCATION=
# export SNATCH_FILENAME=

# export CATCH_FILEPATH=
# export CATCH_FILENAME=

# ... or
source ./client-config.sh

touch $TOKEN_FILE
chmod 600 $TOKEN_FILE

if [[ -f $TOKEN_FILE ]]; then
    TOKEN=$(cat $TOKEN_FILE)
else
    echo "$TOKEN_FILE does not exists. Login first."
fi

JSON='Content-Type: application/json'
AUTH="Authorization: Bearer $TOKEN"

function login() {
    curl -X POST \
         --silent \
         --header "$JSON" \
         --data '{ "email": "'$USER_EMAIL'", "pass": "'$USER_PASS'" }' \
         $AUTH_URL | grep -Po '"token":"\K[^"]*' > $TOKEN_FILE
}

function get() {
    curl -X GET \
         --user $HTTP_USER:$HTTP_PASS \
         $SERVER
}

function options() {
    curl -I -X OPTIONS \
         --user $HTTP_USER:$HTTP_PASS \
         --header "$AUTH" \
         $SERVER
}

function catch() {
    curl -X POST \
         --user $HTTP_USER:$HTTP_PASS \
         --form "file=@$(realpath $CATCH_FILEPATH)" \
         --form "filename=$CATCH_FILENAME" \
         $SERVER
}

function snatch() {
    curl -X POST \
         --header "$AUTH" \
         --data "location=$SNATCH_LOCATION" \
         --data "filename=$SNATCH_FILENAME" \
         $SERVER
}

case $1 in
     login|catch|snatch|options|get)
         $1;;

     *)
         echo "Unknown $1 action."
esac
