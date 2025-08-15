package com.eazybank.eazybank.config;

import com.eazybank.eazybank.exceptionhandling.CustomAccessDeniedHandler;
import com.eazybank.eazybank.filter.CsrfCookieFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@Profile("prod")
public class ProjectSecurityProdConfiguration {

	@Bean
	SecurityFilterChain defaulSecurityFilterChain(HttpSecurity http) throws Exception{
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
		CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
		http.sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.cors(corsConfig -> corsConfig.configurationSource(new CorsConfigurationSource() {
					@Override
					public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
						CorsConfiguration corsConfiguration = new CorsConfiguration();
						corsConfiguration.setAllowedOrigins(Collections.singletonList("https://localhost:4200"));
						corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
						corsConfiguration.setAllowCredentials(true);
						corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
						corsConfiguration.setExposedHeaders(Arrays.asList("Authorization"));
						corsConfiguration.setMaxAge(3600L);
						return corsConfiguration;
					}
				}))
				.csrf(csrfConfig -> csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
						.ignoringRequestMatchers( "/contact","/register")
						.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
				.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
				.requiresChannel(rcc -> rcc.anyRequest().requiresSecure()) // only for https
				.authorizeHttpRequests(requests -> requests
						/*	.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
                    .requestMatchers("myLoans").hasAuthority("VIEWLOANS")
                    .requestMatchers("myBalance").hasAnyAuthority("VIEWBALANCE", "VIEWACCOUNT")
                    .requestMatchers( "myCard").hasAuthority("VIEWCARDS") */
						.requestMatchers("/myAccount").hasRole("USER")
						.requestMatchers("myLoans").authenticated()
						.requestMatchers("myBalance").hasAnyRole("USER","ADMIN")
						.requestMatchers( "myCard").hasRole("USER")
                        .requestMatchers( "/user").authenticated()
                        .requestMatchers("/contact", "/notices", "/register").permitAll());
		http.oauth2ResourceServer(rsc -> rsc.jwt(jwtConfigurer ->
				jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));
		http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
		return http.build();
		
	}


}
