package com.github.irybov.bankdemomvc.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionTemplate;

import com.github.irybov.bankdemomvc.dao.AccountDAO;
import com.github.irybov.bankdemomvc.dao.LoginDAO;
import com.github.irybov.bankdemomvc.jpa.AccountJPA;
import com.github.irybov.bankdemomvc.jpa.LoginJPA;

@ExtendWith(SpringExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
//@Import(LoginListener.class)
class LoginListenerTest {
	
	@Autowired
	private ApplicationEventPublisher publisher;
	
//	@MockBean
//	private LoginJPA loginJPA;
//	@MockBean
//	private LoginDAO loginDAO;
//	@MockBean
//	private AccountJPA accountJPA;
//	@MockBean
//	private AccountDAO accountDAO;
//	@MockBean
//	private TransactionTemplate template;
	@MockBean
	private LoginListener listener;
/*	
	@BeforeAll
	void prepare() {
		ReflectionTestUtils.setField(listener, "loginJPA", loginJPA);
		ReflectionTestUtils.setField(listener, "loginDAO", loginDAO);
		ReflectionTestUtils.setField(listener, "accountJPA", accountJPA);
		ReflectionTestUtils.setField(listener, "accountDAO", accountDAO);
		ReflectionTestUtils.setField(listener, "template", template);
	}
*/	
	@Test
	void test() {		
		doNothing().when(listener).listen(any(AbstractAuthenticationEvent.class));
		
		publisher.publishEvent(new AuthenticationFailureBadCredentialsEvent
				(new UsernamePasswordAuthenticationToken(new Object(), new Object()), 
						new BadCredentialsException(new String())));
		publisher.publishEvent(new AuthenticationSuccessEvent
				(new UsernamePasswordAuthenticationToken(new Object(), new Object())));
		
		verify(listener, times(2)).listen(any(AbstractAuthenticationEvent.class));
	}

}
