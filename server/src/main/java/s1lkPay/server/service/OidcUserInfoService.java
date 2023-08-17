package s1lkPay.server.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;
import s1lkPay.server.domain.entity.SecurityUser;
import s1lkPay.server.repository.UserRepository;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;


@Service
@RequiredArgsConstructor
public class OidcUserInfoService {

    private final UserRepository userRepository;

    public OidcUserInfo loadUser(String username) {
        SecurityUser securityUserOptional = userRepository.findByUsername(username);
        return new OidcUserInfo(createUser(securityUserOptional));
    }

    private Map<String, Object> createUser(SecurityUser securityUser) {

        return OidcUserInfo.builder()
                .name(securityUser.getUsername())
                .claims(stringObjectMap -> {
                    try {
                        stringObjectMap.putAll(convert(securityUser));
                    } catch (IllegalAccessException e) {
                        throw new RuntimeException(e);
                    }
                })
                .build()
                .getClaims();
    }

    public static Map<String, Object> convert(Object object) throws IllegalAccessException {
        Map<String, Object> parameters = new HashMap<>();
        for (Field declaredField : object.getClass().getDeclaredFields()) {
            if(declaredField.getName().equals("password")) continue;
            declaredField.setAccessible(true);
            parameters.put(declaredField.getName(), declaredField.get(object));
        }
        return parameters;
    }

}

