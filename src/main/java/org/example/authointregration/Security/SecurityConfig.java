package org.example.authointregration.Security;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Value("${okta.oauth2.issuer}")
    private String issuer;
    @Value("${okta.oauth2.client-id}")
    private String clientId;

    @Bean
    public SecurityFilterChain configure(HttpSecurity http, OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService) throws Exception {
        http
                .authorizeHttpRequests(auth-> auth
                                .requestMatchers("/admin/**").hasAnyRole("ADMIN","USER")
                                .requestMatchers("/user/**").hasRole("USER")
                                .anyRequest().authenticated()
                        )
                .oauth2Login(oauth2->oauth2
                        .userInfoEndpoint(userInfo->userInfo.oidcUserService(this.oidcUserService())))

                .logout(logout->logout
                        .addLogoutHandler(logoutHandler()));
        return  http.build();
    }

private LogoutHandler logoutHandler() {
        return (request, response, authentication) -> {
            try{
                String baseUrl= ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString();
                response.sendRedirect(issuer+"v2/logout?client_id="+clientId+"$returnTo="+baseUrl);
            }
            catch(IOException e){
                throw  new RuntimeException(e);
            }
        };
}
private OidcUserService oidcUserService(){
        return new OidcUserService (){
        public OidcUser loadUser(OidcUserRequest userRequest) {
            OidcUser oidcUser = super.loadUser(userRequest);

            List<SimpleGrantedAuthority> mappedAuthorities = new ArrayList<>();
            List<String> roles = (List<String>) oidcUser.getClaims().getOrDefault("roles", Collections.emptyList());
            for (String role : roles) {
                mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
            return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
        }   };
}

}
