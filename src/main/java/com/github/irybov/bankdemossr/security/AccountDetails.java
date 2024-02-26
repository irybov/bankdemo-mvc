package com.github.irybov.bankdemossr.security;

import java.util.Collection;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.UserDetails;

import com.github.irybov.bankdemossr.entity.Account;

public class AccountDetails implements UserDetails {

	@Override
	public int hashCode() {
		return Objects.hash(account);
	}
	@Override
	public boolean equals(Object obj) {

		if(obj instanceof AccountDetails) {
			AccountDetails other = (AccountDetails) obj;
			return Objects.equals(account, other.account);
		}
		return false;
	}

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
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
