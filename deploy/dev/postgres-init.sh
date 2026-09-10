#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres --set=nl_password="$NEBULALOG_PASSWORD" --set=kc_password="$KEYCLOAK_PASSWORD" <<'SQL'
CREATE USER nebulalog PASSWORD :'nl_password';
CREATE DATABASE nebulalog OWNER nebulalog;
REVOKE ALL ON DATABASE nebulalog FROM PUBLIC;
CREATE USER keycloak PASSWORD :'kc_password';
CREATE DATABASE keycloak OWNER keycloak;
REVOKE ALL ON DATABASE keycloak FROM PUBLIC;
SQL
