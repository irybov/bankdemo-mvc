package com.github.irybov.bankdemomvc.config;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityBeans {
	
	@Bean
	protected PasswordEncoder bCryptPasswordEncoder() {return new BCryptPasswordEncoder(4);}

	@Bean
	protected AuthenticationEventPublisher authenticationEventPublisher
		(ApplicationEventPublisher applicationEventPublisher) {
		return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
	}
	
}
