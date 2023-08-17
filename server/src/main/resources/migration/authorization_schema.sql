create table if not exists client
(
    id                            varchar primary key,
    authorization_grant_types     varchar(1000)       NOT NULL,
    client_authentication_methods varchar(1000)       NOT NULL,
    client_id                     varchar(100) unique NOT NULL,
    client_id_issued_at           timestamp     DEFAULT CURRENT_TIMESTAMP,
    client_name                   varchar(200)        NOT NULL,
    client_secret                 varchar(200)  DEFAULT NULL,
    client_secret_expires_at      timestamp     DEFAULT CURRENT_TIMESTAMP,
    client_settings               varchar(2000)       NOT NULL,
    redirect_uris                 varchar(1000) DEFAULT NULL,
    scopes                        varchar(1000)       NOT NULL,
    token_settings                varchar(2000)       NOT NULL
);


INSERT INTO client(id, authorization_grant_types, client_authentication_methods, client_id,
                              client_id_issued_at, client_name,
                              client_secret, client_secret_expires_at, client_settings, redirect_uris, scopes,
                              token_settings)
VALUES ('abbc70f1-fb59-4b42-b1e4-c52fa0080bea',
        'refresh_token,client_credentials,authorization_code, urn:ietf:params:oauth:grant-type:jwt-bearer, custom_password',
        'client_secret_basic',
        'abbc70f1-fb59-4b42-b1e4-c52fa0080bea', null, 'abbc70f1-fb59-4b42-b1e4-c52fa0080bea',
        '$2a$10$lcGI9Fp6GLfk7wjyOK0VqORQqMtsQRoC3J7i/V023SgQv9JZLZ01K', null,
        '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":true}',
        'http://127.0.0.1:8080/login/oauth2/code/s1lkPay', 'openid',
        '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,
        "settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],
        "settings.token.access-token-time-to-live":["java.time.Duration",86400.000000000],
        "settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat",
        "value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],
        "settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000]}');


create table if not exists "authorization"
(
    id                            varchar(100) NOT NULL,
    registered_client_id          varchar(100) NOT NULL,
    principal_name                varchar(200) NOT NULL,
    authorization_grant_type      varchar(100) NOT NULL,
    authorized_scopes             varchar(1000) DEFAULT NULL,
    attributes                    text          DEFAULT NULL,
    state                         varchar(500)  DEFAULT NULL,
    authorization_code_value      text          DEFAULT NULL,
    authorization_code_issued_at  timestamp     DEFAULT NULL,
    authorization_code_expires_at timestamp     DEFAULT NULL,
    authorization_code_metadata   text          DEFAULT NULL,
    access_token_value            text          DEFAULT NULL,
    access_token_issued_at        timestamp     DEFAULT NULL,
    access_token_expires_at       timestamp     DEFAULT NULL,
    access_token_metadata         text          DEFAULT NULL,
    access_token_type             varchar(100)  DEFAULT NULL,
    access_token_scopes           varchar(1000) DEFAULT NULL,
    oidc_id_token_value           text          DEFAULT NULL,
    oidc_id_token_issued_at       timestamp     DEFAULT NULL,
    oidc_id_token_expires_at      timestamp     DEFAULT NULL,
    oidc_id_token_metadata        text          DEFAULT NULL,
    refresh_token_value           text          DEFAULT NULL,
    refresh_token_issued_at       timestamp     DEFAULT NULL,
    refresh_token_expires_at      timestamp     DEFAULT NULL,
    refresh_token_metadata        text          DEFAULT NULL,
    oidc_id_token_claims          text          DEFAULT NULL,
    PRIMARY KEY (id)
);

create table if not exists authorization_consent
(
    registered_client_id varchar(100)  NOT NULL,
    principal_name       varchar(200)  NOT NULL,
    authorities          varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);


create table if not exists "users"
(
    id                      bigserial    not null primary key,
    username                varchar(255) not null unique,
    password                varchar(255) not null,
    account_non_expired     bool default true,
    account_non_locked      bool default true,
    credentials_non_expired bool default true,
    enabled                 bool default true
);

insert into users
values (1, 'user', '$2a$10$lcGI9Fp6GLfk7wjyOK0VqORQqMtsQRoC3J7i/V023SgQv9JZLZ01K', default, default, default,
        default);
insert into users
values (2, 'developer', '$2a$10$lcGI9Fp6GLfk7wjyOK0VqORQqMtsQRoC3J7i/V023SgQv9JZLZ01K', default, default, default,
        default);
insert into users
values (3, 'admin', '$2a$10$lcGI9Fp6GLfk7wjyOK0VqORQqMtsQRoC3J7i/V023SgQv9JZLZ01K', default, default, default,
        default);



create table if not exists authorities
(
    id        bigserial not null primary key,
    authority varchar(255)
);

insert into authorities
values (1, 'openid');
insert into authorities
values (2, 'openid');
insert into authorities
values (3, 'openid');


create table if not exists users_authorities
(
    users_id       int not null references users (id),
    authorities_id int not null references authorities (id)
);

insert into users_authorities
values (1, 1)
