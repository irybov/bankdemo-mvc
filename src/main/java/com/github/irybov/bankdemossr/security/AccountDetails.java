package com.github.irybov.bankdemossr.security;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.github.irybov.bankdemossr.entity.Account;

public class AccountDetails implements UserDetails {

	private static final long serialVersionUID = 1L;
	private final Account account;
	public AccountDetails(Account account) {
		this.account = account;
	}	
	public Account getAccount() {
		return this.account;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.account.getRoles();
	}

	@Override
	public String getPassword() {
		return this.account.getPassword();
	}

	@Override
	public String getUsername() {
		return this.account.getPhone();
	}

	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isEnabled() {
		return this.account.isActive();
	}

}
