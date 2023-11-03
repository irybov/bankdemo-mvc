package com.github.irybov.bankdemossr.security;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDate;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.mock.mockito.MockBean;
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
	@MockBean
	@Qualifier("accountServiceAlias")
	private AccountService accountService;
	@InjectMocks
	private AccountDetailsService accountDetailsService;
	private AutoCloseable autoClosable;
	private Account adminEntity;
	
    @BeforeAll
    void set_up() {
    	autoClosable = MockitoAnnotations.openMocks(this);
    	accountDetailsService = new AccountDetailsService();
    	ReflectionTestUtils.setField(accountDetailsService, "repository", accountRepository);
    	ReflectionTestUtils.setField(accountDetailsService, "dao", accountDAO);
    	ReflectionTestUtils.setField(accountDetailsService, "accountService", accountService);
		adminEntity = new Account("Admin", "Adminov", "0000000000", LocalDate.of(2001, 01, 01),
				 BCrypt.hashpw("superadmin", BCrypt.gensalt(4)), true);
		adminEntity.addRole(Role.ADMIN);
    }

	@Test
	void can_load_user() {
		
		String phone = "0000000000";

		if(accountService instanceof AccountServiceJPA) {
			when(accountRepository.findByPhone(phone)).thenReturn(adminEntity);
			assertThat(accountDetailsService.loadUserByUsername(phone))
			.isExactlyInstanceOf(Account.class);
			assertThat(accountDetailsService.loadUserByUsername(phone).getAuthorities().isEmpty())
				.isFalse();
			assertThat(accountDetailsService.loadUserByUsername(phone).isEnabled()).isTrue();
			assertThat(accountDetailsService.loadUserByUsername(phone).getPassword()).isBase64();
			assertThat(accountDetailsService.loadUserByUsername(phone).getUsername())
				.isEqualTo(phone);
			verify(accountRepository).findByPhone(phone);
		}
		else if(accountService instanceof AccountServiceDAO) {
			when(accountDAO.getWithRoles(phone)).thenReturn(adminEntity);
			assertThat(accountDetailsService.loadUserByUsername(phone))
				.isExactlyInstanceOf(Account.class);
			assertThat(accountDetailsService.loadUserByUsername(phone).getAuthorities().isEmpty())
				.isFalse();
			assertThat(accountDetailsService.loadUserByUsername(phone).isEnabled()).isTrue();
			assertThat(accountDetailsService.loadUserByUsername(phone).getPassword()).isBase64();
			assertThat(accountDetailsService.loadUserByUsername(phone).getUsername())
				.isEqualTo(phone);
			verify(accountDAO).getWithRoles(phone);
		}
	}
	
	@Test
	void no_user_found() {
		
		String phone = "9999999999";

		if(accountService instanceof AccountServiceJPA) {
			when(accountRepository.findByPhone(phone)).thenReturn(null);
			verify(accountRepository).findByPhone(phone);
		}
		else if(accountService instanceof AccountServiceDAO) {
			when(accountDAO.getWithRoles(phone)).thenReturn(null);
			verify(accountDAO).getWithRoles(phone);
		}
		assertThatThrownBy(() -> accountDetailsService.loadUserByUsername(phone))
			.isInstanceOf(UsernameNotFoundException.class)
			.hasMessage("User " + phone + " not found");
	}
	
    @AfterAll
    void tear_down() throws Exception {
    	autoClosable.close();
    	accountDetailsService = null;
    	adminEntity = null;
    }

}
