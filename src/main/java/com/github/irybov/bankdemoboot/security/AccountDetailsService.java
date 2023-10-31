package com.github.irybov.bankdemoboot.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.github.irybov.bankdemoboot.dao.AccountDAO;
import com.github.irybov.bankdemoboot.entity.Account;
import com.github.irybov.bankdemoboot.repository.AccountRepository;
import com.github.irybov.bankdemoboot.service.AccountService;
import com.github.irybov.bankdemoboot.service.AccountServiceDAO;
import com.github.irybov.bankdemoboot.service.AccountServiceJPA;

@Service
public class AccountDetailsService implements UserDetailsService {
	
	@Autowired
	private AccountRepository repository;
	@Autowired
	private AccountDAO dao;
	@Autowired
	private ApplicationContext context;
	@Autowired
	@Qualifier("accountServiceAlias")
	private AccountService accountService;
		
	@Override
	public UserDetails loadUserByUsername(String phone) throws UsernameNotFoundException {
		
//		accountService = context.getBean(AccountService.class);
		Account account = null;
		if(accountService instanceof AccountServiceJPA) {
			account = repository.findByPhone(phone);			
		}
		else if(accountService instanceof AccountServiceDAO) {
			account = dao.getAccount(phone);
		}
		if(account == null) throw new UsernameNotFoundException("User " + phone + " not found");	
		return new AccountDetails(account);
	}

	public String setServiceImpl(String impl) {
		
		if(impl.equals("JPA")) accountService = (AccountService) context.getBean("accountServiceJPA");
		else if(impl.equals("DAO")) accountService = (AccountService) context.getBean("accountServiceDAO");
		return accountService.getClass().getSimpleName();
	}
	
}
