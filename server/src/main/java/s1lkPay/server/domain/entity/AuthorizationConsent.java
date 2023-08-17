package s1lkPay.server.domain.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

/**
 * Согласие
 */

@IdClass(AuthorizationConsent.AuthorizationConsentId.class)
@Entity
@Getter
@Setter
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "authorization_consent", schema = "public")
public class AuthorizationConsent {

    @Id
    @Column(name = "registered_client_id")
    String registeredClientId;
    @Id
    @Column(name = "principal_name")

    String principalName;
    @Column(name = "authorities")
    String authorities;

    @Getter
    @Setter
    public static class AuthorizationConsentId implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
        private String registeredClientId;
        private String principalName;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AuthorizationConsentId that = (AuthorizationConsentId) o;
            return registeredClientId.equals(that.registeredClientId) && principalName.equals(that.principalName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(registeredClientId, principalName);
        }
    }
}