package com.github.irybov.bankdemossr.repository;

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
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import com.github.irybov.bankdemossr.entity.Account;
import com.github.irybov.bankdemossr.entity.Bill;
import com.github.irybov.bankdemossr.repository.BillRepository;

@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DataJpaTest
class BillRepositoryTest {
	
	@Autowired
	private BillRepository billRepository;
	
	private Bill bill;
	private Account account;
	
	@BeforeAll
	void prepare() {
    	billRepository.deleteAll();
		account = new Account
				("Kylie", "Bunbury", "4444444444", LocalDate.of(1989, 01, 30), "blackmamba", true);
		bill = new Bill("SEA", true, account);
		billRepository.save(bill);
	}

	@Test
	void multi_test() {
		
		int id = bill.getId();
		Optional<Bill> fromDB = billRepository.findById(id);
		assertThat(fromDB.get()).isEqualTo(bill);
		fromDB.get().setBalance(fromDB.get().getBalance().add(BigDecimal.valueOf(9.99)));
		billRepository.save(fromDB.get());
		Optional<Bill> updated = billRepository.findById(id);
		assertThat(updated.get().getBalance()).isEqualTo(BigDecimal.valueOf(9.99));
		assertThat(updated.get()).isEqualTo(fromDB.get());
		billRepository.deleteById(id);
		List<Bill> bills = (List<Bill>) billRepository.findAll();
		assertThat(bills.size()).isEqualTo(0);
		
		bills = billRepository.findByOwnerId(1);
		assertThat(bills.size()).isEqualTo(0);
	}

    @AfterAll
    void clear() {
    	bill = null;
    	account = null;
    }
	
}
