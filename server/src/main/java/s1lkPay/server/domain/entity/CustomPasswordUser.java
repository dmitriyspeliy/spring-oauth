package s1lkPay.server.domain.entity;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public record CustomPasswordUser(String username, Collection<GrantedAuthority> authorities) {

}