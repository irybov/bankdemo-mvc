package com.github.irybov.bankdemomvc.dao;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.InjectMocks;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionTemplate;

import com.github.irybov.bankdemomvc.entity.Account;
import com.github.irybov.bankdemomvc.entity.Login;
import com.github.irybov.bankdemomvc.entity.LoginFailure;
import com.github.irybov.bankdemomvc.entity.LoginSuccess;
import com.github.irybov.bankdemomvc.entity.LoginFailure.LoginFailureBuilder;
import com.github.irybov.bankdemomvc.entity.LoginSuccess.LoginSuccessBuilder;

@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DataJpaTest
class LoginDAOTest {
	
	@PersistenceContext
	private EntityManager entityManager;
	@InjectMocks
	private LoginDAO loginDAO;
    private LoginSuccessBuilder<?, ?> success;
    private LoginFailureBuilder<?, ?> failure;
    private List<Login> logins;
	private Account account;
    @Autowired
    private TransactionTemplate template;
	
	@BeforeAll
	void prepare() {
		ReflectionTestUtils.setField(loginDAO, "entityManager", entityManager);
		
		account = new Account
				("Kylie", "Bunbury", "4444444444", "bunbury@greenmail.io", LocalDate.of(1989, 01, 30), "blackmamba", true);
		template.executeWithoutResult(status ->  {entityManager.persist(account);});	
		
		logins = new ArrayList<>();
		success = LoginSuccess.builder();
		Login successful = success
								.account(account)
								.sourceIp("XYZ")
								.createdAt(OffsetDateTime.now())
								.build();
		logins.add(successful);
		failure = LoginFailure.builder();
		for(int i = 0; i < 3; i++) {
			Login fail = failure
							.account(account)
							.sourceIp("XYZ")
							.createdAt(OffsetDateTime.now())
							.build();
			logins.add(fail);
		}
		template.executeWithoutResult(status ->  {logins.forEach(loginDAO::saveLogin);});
	}

	@Test
	void can_retrieve_login_fails() {
		assertThat(loginDAO.getByTime
				(account.getId(), OffsetDateTime.now().minusHours(1L)).size() == 3);
	}

    @AfterAll
    void clear() {
    	account = null;
    	logins = null;
    	success = null;
    	failure = null;
    }
	
}
