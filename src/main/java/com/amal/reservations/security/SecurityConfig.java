package com.amal.reservations.security;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import
org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;
@Configuration
@EnableWebSecurity
public class SecurityConfig {
	@Autowired 
	KeycloakRoleConverter keycloakRoleConverter; 
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf().disable().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
		 .cors().configurationSource(new CorsConfigurationSource() {
		 @Override
		 public CorsConfiguration getCorsConfiguration(HttpServletRequest
		request) {
		 CorsConfiguration config = new CorsConfiguration();

		config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
		 config.setAllowedMethods(Collections.singletonList("*"));
		 config.setAllowCredentials(true);
		 config.setAllowedHeaders(Collections.singletonList("*"));
		 config.setExposedHeaders(Arrays.asList("Authorization"));
		 config.setMaxAge(3600L);
		 return config;
		 }
		 }).and()

		
		.authorizeHttpRequests( requests -> 
		requests.requestMatchers("/api/all/**").permitAll()  //.hasAnyAuthority("ADMIN","USER") 
		.requestMatchers(HttpMethod.GET,"/api/getbyid/**").hasAnyAuthority("ADMIN","USER") 
		// .requestMatchers(HttpMethod.POST,"/api/addprod/**").hasAuthority("ADMIN") 
		.requestMatchers(HttpMethod.PUT,"/api/updateprod/**").hasAuthority("ADMIN") 
		.requestMatchers(HttpMethod.DELETE,"/api/delprod/**").hasAuthority("ADMIN") 
		.anyRequest().authenticated() ) 
		.oauth2ResourceServer(ors->ors.jwt(jwt-> 
		jwt.jwtAuthenticationConverter(keycloakRoleConverter))); 
		//.oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults())); 
	return http.build();
	}

}

