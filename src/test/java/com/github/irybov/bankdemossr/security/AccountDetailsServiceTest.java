package com.github.irybov.bankdemossr.security;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDate;
import java.util.Optional;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.util.ReflectionTestUtils;

import com.github.irybov.bankdemossr.dao.AccountDAO;
import com.github.irybov.bankdemossr.entity.Account;
import com.github.irybov.bankdemossr.repository.AccountRepository;
import com.github.irybov.bankdemossr.service.AccountService;
import com.github.irybov.bankdemossr.service.AccountServiceDAO;
import com.github.irybov.bankdemossr.service.AccountServiceJPA;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AccountDetailsServiceTest {

	@Mock
	private AccountRepository accountRepository;
	@Mock
	private AccountDAO accountDAO;
/*	@MockBean
	@Qualifier("accountServiceAlias")
	private AccountService accountService;*/
	@InjectMocks
	private AccountDetailsService accountDetailsService;
	private AutoCloseable autoClosable;
	private Account adminEntity;
	
//	@Value("${bean.service-impl}")
	private String impl;
	
    @BeforeAll
    void set_up() {

    	autoClosable = MockitoAnnotations.openMocks(this);
    	accountDetailsService = new AccountDetailsService();
    	ReflectionTestUtils.setField(accountDetailsService, "repository", accountRepository);
    	ReflectionTestUtils.setField(accountDetailsService, "dao", accountDAO);
//    	ReflectionTestUtils.setField(accountDetailsService, "accountService", accountService);
//    	ReflectionTestUtils.setField(accountDetailsService, "impl", impl);
		adminEntity = new Account("Admin", "Adminov", "0000000000", LocalDate.of(2001, 01, 01),
				 BCrypt.hashpw("superadmin", BCrypt.gensalt(4)), true);
		adminEntity.addRole(Role.ADMIN);
    }

	@Test
	void can_load_user() {
		
		String phone = "0000000000";
		
		impl = "JPA";
		accountDetailsService.setImpl(impl);
//    	ReflectionTestUtils.setField(accountDetailsService, "impl", impl);
//		if(accountService instanceof AccountServiceJPA) {
			when(accountRepository.findByPhone(phone)).thenReturn(Optional.of(adminEntity));
			UserDetails details = accountDetailsService.loadUserByUsername(phone);
			assertThat(details).isInstanceOf(UserDetails.class);
			assertThat(details.getAuthorities().isEmpty()).isFalse();
			assertThat(details.isEnabled()).isTrue();
			assertThat(BCrypt.checkpw("superadmin", details.getPassword())).isTrue();
			assertThat(details.getUsername()).isEqualTo(phone);
			verify(accountRepository).findByPhone(phone);

		impl = "DAO";
		accountDetailsService.setImpl(impl);
//	    ReflectionTestUtils.setField(accountDetailsService, "impl", impl);
//		else if(accountService instanceof AccountServiceDAO) {
			when(accountDAO.getWithRoles(phone)).thenReturn(adminEntity);
			details = accountDetailsService.loadUserByUsername(phone);
			assertThat(details).isInstanceOf(UserDetails.class);
			assertThat(details.getAuthorities().isEmpty()).isFalse();
			assertThat(details.isEnabled()).isTrue();
			assertThat(BCrypt.checkpw("superadmin", details.getPassword())).isTrue();
			assertThat(details.getUsername()).isEqualTo(phone);
			verify(accountDAO).getWithRoles(phone);
	}
	
	@Test
	void no_user_found() {
		
		String phone = "9999999999";

		impl = "JPA";
    	ReflectionTestUtils.setField(accountDetailsService, "impl", impl);
//		if(accountService instanceof AccountServiceJPA) {
			when(accountRepository.findByPhone(phone)).thenReturn(Optional.empty());
			assertThatThrownBy(() -> accountDetailsService.loadUserByUsername(phone))
				.isInstanceOf(UsernameNotFoundException.class)
				.hasMessage("User " + phone + " not found");
			verify(accountRepository).findByPhone(phone);
			
		impl = "DAO";
		ReflectionTestUtils.setField(accountDetailsService, "impl", impl);
//		else if(accountService instanceof AccountServiceDAO) {
			when(accountDAO.getWithRoles(phone)).thenReturn(null);
			assertThatThrownBy(() -> accountDetailsService.loadUserByUsername(phone))
				.isInstanceOf(UsernameNotFoundException.class)
				.hasMessage("User " + phone + " not found");
			verify(accountDAO).getWithRoles(phone);
	}
	
    @AfterAll
    void tear_down() throws Exception {
    	autoClosable.close();
    	accountDetailsService = null;
    	adminEntity = null;
    	impl = null;
    }

}
