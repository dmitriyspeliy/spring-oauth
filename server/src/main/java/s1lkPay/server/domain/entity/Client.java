package s1lkPay.server.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

import java.time.Instant;

/**
 * Клиент
 */

@Entity
@Getter
@Setter
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "client", schema = "public")
public class Client {

    @Id
    @Column(name = "id")
    private String id;
    @Column(name = "client_id")
    private String clientId;
    @Column(name = "client_id_issued_at")
    private Instant clientIdIssuedAt;
    @Column(name = "client_secret")
    private String clientSecret;
    @Column(name = "client_secret_expires_at")
    private Instant clientSecretExpiresAt;
    @Column(name = "client_name")
    private String clientName;
    @Column(name = "client_authentication_methods")
    private String clientAuthenticationMethods;
    @Column(name = "authorization_grant_types")
    private String authorizationGrantTypes;
    @Column(name = "redirect_uris")
    private String redirectUris;
    @Column(name = "scopes")
    private String scopes;
    @Column(name = "client_settings")
    private String clientSettings;
    @Column(name = "token_settings")
    private String tokenSettings;


}