package com.github.irybov.bankdemomvc.dao;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.time.LocalDate;
import java.time.Month;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.persistence.EntityManager;
//import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
//import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
//import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.InjectMocks;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.util.ReflectionTestUtils;

import com.github.irybov.bankdemomvc.dao.AccountDAO;
import com.github.irybov.bankdemomvc.entity.Account;
import com.github.irybov.bankdemomvc.security.Role;

@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
//@TestMethodOrder(OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DataJpaTest
class AccountDAOTest {
	
	@PersistenceContext
	private EntityManager entityManager;
	@InjectMocks
	private AccountDAO accountDAO;

	private String oldPN;
	private String newPN;
	private Account account;
	
	@BeforeAll
	void prepare() {
		ReflectionTestUtils.setField(accountDAO, "entityManager", entityManager);
		oldPN = new String("0000000000");
		newPN = new String("9999999999");
	}
	
	@BeforeEach
	void set_up() {
		entityManager.createNativeQuery("DELETE FROM {h-schema}bills").executeUpdate();
		entityManager.createNativeQuery("DELETE FROM {h-schema}roles").executeUpdate();
		entityManager.createNativeQuery("DELETE FROM {h-schema}accounts").executeUpdate();
		account = new Account
				("Admin", "Adminov", "0000000000", LocalDate.of(2001, 01, 01), "superadmin", true);
		account.addRole(Role.ADMIN);
		accountDAO.saveAccount(account);
	}
	
	@Test
//	@Order(1)
	void check_that_phone_present() {
        assertThat(accountDAO.getPhone(oldPN).get()).isEqualTo(account.getPhone());
	}
	
    @Test
//	@Order(2)
	void check_that_phone_not_present() {
//		assertThatExceptionOfType(NoResultException.class)
//		.isThrownBy(() -> {accountDAO.getPhone(newPN);});
		assertThat(accountDAO.getPhone(newPN)).isEmpty();
	}
	
	@Test
//	@Order(3)
	void search_by_phone() {
		Account fromDB = accountDAO.getAccount(oldPN);
		assertThat(fromDB).isEqualTo(account);
		fromDB = accountDAO.getWithBills(oldPN);
		assertThat(fromDB).isEqualTo(account);
	}

	@Test
//	@Order(4)
	void update_and_compare() {
		Account fromDB = accountDAO.getAccount(oldPN);
		fromDB.setPhone(newPN);
		accountDAO.updateAccount(fromDB);
		Account updated = accountDAO.getAccount(newPN);		
		assertThat(fromDB).isEqualTo(updated);
	}
    
    @Test
//	@Order(5)
    void check_for_clients_presence() {
    	List<Account> clients = accountDAO.getAll();
    	assertThat(clients).isNotNull();
    	assertThat(clients.isEmpty()).isTrue();
    	
		Account vixenEntity = new Account
		("Kae", "Yukawa", "1111111111", LocalDate.of(1985, Month.AUGUST, 31), "supervixen", true);
		vixenEntity.addRole(Role.CLIENT);
		Account blondeEntity = new Account
		("Hannah", "Waddingham", "2222222222", LocalDate.of(1974, Month.JULY, 28), "bustyblonde", true);
		blondeEntity.addRole(Role.CLIENT);
		Account gingerEntity = new Account
		("Ella", "Hughes", "3333333333", LocalDate.of(1995, Month.JUNE, 13), "gingerchick", true);
//		gingerEntity.addRole(Role.CLIENT);
		gingerEntity.addRole(Role.ADMIN);
		
    	List<Account> whores = new ArrayList<>();
    	Collections.addAll(whores, vixenEntity, blondeEntity, gingerEntity);
    	whores.forEach(accountDAO::saveAccount);
    	
    	clients = accountDAO.getAll();
    	assertThat(clients.isEmpty()).isFalse();
    	assertThat(clients.size()).isEqualTo(whores.size() - 1);
    }
    
    @Test
//	@Order(6)
    void produce_persistence_exception() {
		Account fakeAdmin = new Account
				("Admin", "Adminov", "0000000000", LocalDate.of(2001, 01, 01), "superadmin", true);
		fakeAdmin.addRole(Role.CLIENT);
		assertThatExceptionOfType(PersistenceException.class)
				.isThrownBy(() -> {accountDAO.saveAccount(fakeAdmin);});
    }
	
    @AfterEach
    void tear_down() {
    	accountDAO.deleteAccount(account);
    	account = null;
    }
    
    @AfterAll
    void clear() {
    	oldPN = null;
    	newPN = null;
    }
    
}
