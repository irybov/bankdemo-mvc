package com.github.irybov.bankdemomvc.security;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDate;
import java.time.Month;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import com.github.irybov.bankdemomvc.dao.AccountDAO;
import com.github.irybov.bankdemomvc.entity.Account;
import com.github.irybov.bankdemomvc.jpa.AccountJPA;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UnlockServiceTest {
	
	@Mock
	private AccountJPA accountJPA;
	@Mock
	private AccountDAO accountDAO;
	@Mock
	private TransactionTemplate template;
	@InjectMocks
	private UnlockService unlockService;
	private AutoCloseable autoClosable;
	private String impl;
	
	@Captor
	private ArgumentCaptor<Consumer<TransactionStatus>> captor;
	
    @BeforeAll
    void set_up() {
    	autoClosable = MockitoAnnotations.openMocks(this);
    	unlockService = new UnlockService();
//    	template = new TransactionTemplate();
    	ReflectionTestUtils.setField(unlockService, "jpa", accountJPA);
    	ReflectionTestUtils.setField(unlockService, "dao", accountDAO);
    	ReflectionTestUtils.setField(unlockService, "template", template);
    }

	@Test
	void test() {
		
		List<Account> empty = Collections.emptyList();
    	Account black = new Account
			("Kylie", "Bunbury", "4444444444", "bunbury@greenmail.io", LocalDate.of(1989, 01, 30), "blackmamba", false);
		Account vixen = new Account
			("Kae", "Yukawa", "1111111111", "yukawa@greenmail.io", LocalDate.of(1985, Month.AUGUST, 31), "supervixen", false);
		Account blonde = new Account
			("Hannah", "Waddingham", "2222222222", "waddingham@greenmail.io", LocalDate.of(1974, Month.JULY, 28), "bustyblonde", false);
		Account ginger = new Account
			("Ella", "Hughes", "3333333333", "hughes@greenmail.io", LocalDate.of(1995, Month.JUNE, 13), "gingerchick", false);
		List<Account> locked = Stream.of(black, vixen, blonde, ginger).collect(Collectors.toList());

//		doNothing().when(template).setReadOnly(any(Boolean.class));
//		doCallRealMethod().when(template).setReadOnly(any(Boolean.class));
		when(template.execute(any(TransactionCallback.class))).thenReturn(empty);
		impl = "JPA";
		unlockService.setImpl(impl);
		unlockService.unlock();
		
		impl = "DAO";
		unlockService.setImpl(impl);
		unlockService.unlock();
		
		when(template.execute(any(TransactionCallback.class))).thenReturn(locked);
		doNothing().when(template).executeWithoutResult
			((Consumer<TransactionStatus>) any(TransactionCallback.class));
		impl = "JPA";
		unlockService.setImpl(impl);
		unlockService.unlock();
		
		impl = "DAO";
		unlockService.setImpl(impl);
		unlockService.unlock();
		
		assertThat(locked.size() == 4);
		verify(template, times(4)).execute(any(TransactionCallback.class));
		verify(template, times(2)).executeWithoutResult(captor.capture());
		verify(template, times(4)).setReadOnly(any(Boolean.class));
	}

    @AfterAll
    void tear_down() throws Exception {
    	autoClosable.close();
    	unlockService = null;
    	impl = null;
    }
	
}
