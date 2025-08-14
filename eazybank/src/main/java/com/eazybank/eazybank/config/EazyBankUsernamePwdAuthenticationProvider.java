package com.eazybank.eazybank.config;

import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@Profile("!prod")
public class EazyBankUsernamePwdAuthenticationProvider implements AuthenticationProvider {

    private final EazyBankUserDetailsService eazyBankUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    public EazyBankUsernamePwdAuthenticationProvider(EazyBankUserDetailsService eazyBankUserDetailsService, PasswordEncoder passwordEncoder) {
        this.eazyBankUserDetailsService = eazyBankUserDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();
        UserDetails userDetails = eazyBankUserDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(username, pwd, userDetails.getAuthorities());

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
