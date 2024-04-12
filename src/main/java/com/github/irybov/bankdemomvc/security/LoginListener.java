package com.github.irybov.bankdemomvc.security;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import com.github.irybov.bankdemomvc.dao.AccountDAO;
import com.github.irybov.bankdemomvc.dao.LoginDAO;
import com.github.irybov.bankdemomvc.entity.Account;
import com.github.irybov.bankdemomvc.entity.Login;
import com.github.irybov.bankdemomvc.entity.LoginFailure;
import com.github.irybov.bankdemomvc.entity.LoginFailure.LoginFailureBuilder;
import com.github.irybov.bankdemomvc.entity.LoginSuccess;
import com.github.irybov.bankdemomvc.entity.LoginSuccess.LoginSuccessBuilder;
import com.github.irybov.bankdemomvc.jpa.AccountJPA;
import com.github.irybov.bankdemomvc.jpa.LoginJPA;

@Component
public class LoginListener {
	
	@Autowired
	private LoginJPA loginJPA;
	@Autowired
	private LoginDAO loginDAO;
	@Autowired
	private AccountJPA accountJPA;
	@Autowired
	private AccountDAO accountDAO;
	
	private Account account;
	private String impl;
	@Autowired
	public void setImpl(@Value("${bean.service-impl}") String impl) {this.impl = impl;}
	public String getImpl() {return this.impl;}
	
	private UsernamePasswordAuthenticationToken token;
	private WebAuthenticationDetails details;
	
    @Autowired
    private TransactionTemplate template;
	
	@EventListener
	public void listen(AbstractAuthenticationEvent event) {
		
		if(event.getSource() instanceof UsernamePasswordAuthenticationToken) {
			token = (UsernamePasswordAuthenticationToken) event.getSource();
		}
		if(token.getDetails() instanceof WebAuthenticationDetails) {
			details = (WebAuthenticationDetails) token.getDetails();
		}
		if(token.getPrincipal() instanceof String) {
			String phone = (String) token.getPrincipal();
			
			template.setReadOnly(true);
			if(impl.equals("JPA")) {
				Optional<Account> optional  = template.execute(status ->  {
					return accountJPA.findByPhone(phone);
				});
				account = optional.orElseThrow(() -> 
						new UsernameNotFoundException("User " + phone + " not found"));
			}
			else if(impl.equals("DAO")) {
				account = template.execute(status ->  {return accountDAO.getAccount(phone);});
				if(account == null) throw new UsernameNotFoundException
										("User " + phone + " not found");
			}
			template.setReadOnly(false);
		}
		
		if(event instanceof AuthenticationFailureBadCredentialsEvent) {
			
			LoginFailureBuilder<?, ?> builder = LoginFailure.builder();
			builder
				.account(account)
				.sourceIp(details.getRemoteAddress())
				.createdAt(OffsetDateTime.now());
			
			Login failure = null;
			template.setReadOnly(true);
			if(impl.equals("JPA")) {
				failure = template.execute(status ->  {
					return loginJPA.saveAndFlush(builder.build());
				});
			}
			else if(impl.equals("DAO")) {
				failure = template.execute(status ->  {
					return loginDAO.saveLogin(builder.build());
				});
			}
			template.setReadOnly(false);
			
			if(failure.getAccount() != null) {lockAccount(failure.getAccount().getId());}
		}
		else if(event instanceof AuthenticationSuccessEvent) {
			
			LoginSuccessBuilder<?, ?> builder = LoginSuccess.builder();
			builder
				.account(account)
				.sourceIp(details.getRemoteAddress())
				.createdAt(OffsetDateTime.now());
			
			if(impl.equals("JPA")) {
				template.executeWithoutResult(status ->  {loginJPA.saveAndFlush(builder.build());});
			}
			else if(impl.equals("DAO")) {
				template.executeWithoutResult(status ->  {loginDAO.saveLogin(builder.build());});
			}
		}		
	}
	private void lockAccount(int id) {
		List<? extends Login> failures = null;
		
		template.setReadOnly(true);
		if(impl.equals("JPA")) {
			failures = template.execute(status ->  {
				return loginJPA.findByAccountIdAndCreatedAtIsAfter
						(id, OffsetDateTime.now().minusHours(1L));
			});
		}
		else if(impl.equals("DAO")) {
			failures = template.execute(status ->  {
				return loginDAO.getByTime(id, OffsetDateTime.now().minusHours(1L));
			});
		}		
		template.setReadOnly(false);
		
		if(failures.size() > 2) {
			account.setActive(false);
			
			if(impl.equals("JPA")) {
				template.executeWithoutResult(status ->  {accountJPA.save(account);});
			}
			else if(impl.equals("DAO")) {
				template.executeWithoutResult(status ->  {accountDAO.updateAccount(account);});
			}
		}
	}
	
}
