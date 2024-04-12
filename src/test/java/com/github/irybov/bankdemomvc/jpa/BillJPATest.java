package com.github.irybov.bankdemomvc.jpa;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.support.TransactionTemplate;

import com.github.irybov.bankdemomvc.entity.Account;
import com.github.irybov.bankdemomvc.entity.Bill;
import com.github.irybov.bankdemomvc.jpa.AccountJPA;
import com.github.irybov.bankdemomvc.jpa.BillJPA;

@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DataJpaTest
//@EnableJpaRepositories(basePackageClasses = {BillJPA.class, AccountJPA.class})
//@EntityScan(basePackageClasses = {Bill.class, Account.class})
class BillJPATest {
	
    @Autowired
    private TransactionTemplate template;

	@Autowired
	private AccountJPA accountJPA;
	@Autowired
	private BillJPA billJPA;
	
	private Bill bill;
	private Account account;
	
	@BeforeAll
	void prepare() {
		
		account = new Account
				("Kylie", "Bunbury", "4444444444", LocalDate.of(1989, 01, 30), "blackmamba", true);
		bill = new Bill("SEA", true, account);
		
		template.executeWithoutResult(status ->  {
			billJPA.deleteAll();
			billJPA.save(bill);
			accountJPA.save(account);
		});
	}

	@Test
	void multi_test() {
		
		int id = bill.getId();
		Optional<Bill> fromDB = billJPA.findById(id);
		assertThat(fromDB.get()).isEqualTo(bill);
		fromDB.get().setBalance(fromDB.get().getBalance().add(BigDecimal.valueOf(9.99)));
		billJPA.save(fromDB.get());
		Optional<Bill> updated = billJPA.findById(id);
		assertThat(updated.get().getBalance()).isEqualTo(BigDecimal.valueOf(9.99));
		assertThat(updated.get()).isEqualTo(fromDB.get());
		billJPA.deleteById(id);
		List<Bill> bills = billJPA.findAll();
		assertThat(bills.size()).isEqualTo(0);
		
		bills = billJPA.findByOwnerId(4);
		assertThat(bills.size()).isEqualTo(0);
	}

    @AfterAll
    void clear() {
    	bill = null;
    	template.executeWithoutResult(status ->  {accountJPA.deleteById(account.getId());});
    	account = null;
    }
	
}
