package com.github.irybov.bankdemoboot.security;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority{
	ADMIN, CLIENT, REMOTE;

	@Override
	public String getAuthority() {
		return "ROLE_" + name();
	}
}
