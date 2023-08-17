package s1lkPay.server.domain.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

import java.time.Instant;

/**
 * Аутентификация
 */

@Entity
@Getter
@Setter
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "authorization", schema = "public")
public class Authorization {

    @Id
    @Column(name = "id")
    String id;
    @Column(name = "registered_client_id")
    String registeredClientId;
    @Column(name = "principal_name")
    String principalName;
    @Column(name = "authorization_grant_type")
    String authorizationGrantType;
    @Column(name = "authorized_scopes")
    String authorizedScopes;
    @Column(name = "attributes")
    String attributes;
    @Column(name = "state")
    String state;
    @Column(name = "authorization_code_value")
    String authorizationCodeValue;
    @Column(name = "authorization_code_issued_at")
    Instant authorizationCodeIssuedAt;
    @Column(name = "authorization_code_expires_at")
    Instant authorizationCodeExpiresAt;
    @Column(name = "authorization_code_metadata")
    String authorizationCodeMetadata;
    @Column(name = "access_token_value")
    String accessTokenValue;
    @Column(name = "access_token_issued_at")
    Instant accessTokenIssuedAt;
    @Column(name = "access_token_expires_at")
    Instant accessTokenExpiresAt;
    @Column(name = "access_token_metadata")
    String accessTokenMetadata;
    @Column(name = "access_token_type")
    String accessTokenType;
    @Column(name = "access_token_scopes")
    String accessTokenScopes;
    @Column(name = "refresh_token_value")
    String refreshTokenValue;
    @Column(name = "refresh_token_issued_at")
    Instant refreshTokenIssuedAt;
    @Column(name = "refresh_token_expires_at")
    Instant refreshTokenExpiresAt;
    @Column(name = "refresh_token_metadata")
    String refreshTokenMetadata;
    @Column(name = "oidc_id_token_value")
    String oidcIdTokenValue;
    @Column(name = "oidc_id_token_issued_at")
    Instant oidcIdTokenIssuedAt;
    @Column(name = "oidc_id_token_expires_at")
    Instant oidcIdTokenExpiresAt;
    @Column(name = "oidc_id_token_metadata")
    String oidcIdTokenMetadata;
    @Column(name = "oidc_id_token_claims")
    String oidcIdTokenClaims;

}