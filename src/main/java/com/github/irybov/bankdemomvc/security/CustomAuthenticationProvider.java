package com.github.irybov.bankdemomvc.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.irybov.bankdemomvc.entity.Account;

//@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
	
	@Autowired
	private AccountDetailsService accountDetailsService;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private Cache<String, String> cache;

	@Override
	public Authentication authenticate(Authentication auth) throws AuthenticationException {
		
//        final String phone = auth.getName();
        final String password = auth.getCredentials().toString();        
        final AccountDetails details = accountDetailsService.loadUserByUsername(auth.getName());
//        final Account account = details.getAccount();
        
        if(!passwordEncoder.matches(password, details.getPassword())) {
            throw new BadCredentialsException("Wrong password");
        }
        
        if(auth.getDetails() instanceof CustomWebAuthenticationDetails) {
        	String code = ((CustomWebAuthenticationDetails) auth.getDetails()).getCode();
        	code.trim();
        	if(code == null || code.isEmpty()) {
        		throw new BadCredentialsException("Absent verfication code");
        	}
        	if(!cache.getIfPresent(details.getAccount().getEmail()).equals(code)) {
        		throw new BadCredentialsException("Invalid verfication code");
        	}
        	return new UsernamePasswordAuthenticationToken(details, password, details.getAuthorities());
        }
        else {
        	return new UsernamePasswordAuthenticationToken(details, password, 
        			Arrays.asList(new SimpleGrantedAuthority("ROLE_TEMP")));
        }
        
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

}
