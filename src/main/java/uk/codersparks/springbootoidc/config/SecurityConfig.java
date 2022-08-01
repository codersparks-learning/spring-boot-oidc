package uk.codersparks.springbootoidc.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    public static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);


    public static final String REALM_ACCESS_KEY = "realm_access";
    public static final String ROLES_KEY = "roles";

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, GrantedAuthoritiesMapper authoritiesMapper) throws Exception {
        http.authorizeHttpRequests(a -> a.anyRequest().authenticated())
                .oauth2Login()
                .userInfoEndpoint()
                .userAuthoritiesMapper(authoritiesMapper);
        return http.build();
    }

    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return authorities -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>(authorities);

            var authority = authorities.iterator().next();


            boolean isOidc = authority instanceof OidcUserAuthority;

            logger.debug("Is OIDC?: " + isOidc);

            if( isOidc) {
                var oidcUserAuthority = (OidcUserAuthority) authority;
                logger.debug("Authority: " + oidcUserAuthority);
                var userInfo = oidcUserAuthority.getUserInfo();


                if(userInfo.hasClaim(REALM_ACCESS_KEY)) {
                    var realmAccess = userInfo.getClaimAsMap(REALM_ACCESS_KEY);
                    var roles = (Collection<String>) realmAccess.get(ROLES_KEY);
                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
                }
            } else {
                var oauth2UserAuthority = (OAuth2UserAuthority) authority;
                Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                if(userAttributes.containsKey(REALM_ACCESS_KEY)) {
                    var realmAccess = (Map<String, Object>) userAttributes.get(REALM_ACCESS_KEY);
                    var roles = (Collection<String>) realmAccess.get(ROLES_KEY);
                    mappedAuthorities.addAll(generateAuthoritiesFromClaim(roles));
                }
            }

            return mappedAuthorities;
        };

    }

    private Collection<GrantedAuthority> generateAuthoritiesFromClaim(Collection<String> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
    }
}
