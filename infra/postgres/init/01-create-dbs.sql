-- Creates Keycloak database and user
CREATE USER keycloak WITH PASSWORD 'dev_only_change_me';
CREATE DATABASE keycloak OWNER keycloak;
