package com.eazybank.eazybank.config;

import com.eazybank.eazybank.events.AuthoritiesLoggingAfterFilter;
import com.eazybank.eazybank.exceptionhandling.CustomAccessDeniedHandler;
import com.eazybank.eazybank.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import com.eazybank.eazybank.filter.CsrfCookieFilter;
import com.eazybank.eazybank.filter.JWTTokenGeneratorFilter;
import com.eazybank.eazybank.filter.JWTTokenValidatorFilter;
import com.eazybank.eazybank.filter.RequestValidationBeforeFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
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
						.ignoringRequestMatchers( "/contact","/register", "/apiLogin")
						.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
				.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
				.addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class)
				.addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)
				.addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
				.addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
				.addFilterAt(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
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
                        .requestMatchers("/contact", "/notices", "/register", "/invalidSession", "/apiLogin").permitAll());
		http.formLogin(Customizer.withDefaults());
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
		http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
		return http.build();
		
	}

	// Creating multiple users
	/*
	@Bean
	public UserDetailsService userDetailsService(DataSource dataSource){
		return new JdbcUserDetailsManager(dataSource);
	}
	 */

	@Bean
	public PasswordEncoder passwordEncoder(){
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
													   PasswordEncoder passwordEncoder) {
		EazyBankProdUsernamePwdAuthenticationProvider authenticationProvider =
				new EazyBankProdUsernamePwdAuthenticationProvider((EazyBankUserDetailsService) userDetailsService, passwordEncoder);
		ProviderManager providerManager = new ProviderManager(authenticationProvider);
		providerManager.setEraseCredentialsAfterAuthentication(false);
		return  providerManager;
	}

}
