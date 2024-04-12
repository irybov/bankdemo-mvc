package com.github.irybov.bankdemomvc.jpa;

import java.time.OffsetDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.github.irybov.bankdemomvc.entity.Login;
import com.github.irybov.bankdemomvc.entity.LoginFailure;

public interface LoginJPA extends JpaRepository<Login, Long> {

	List<LoginFailure> findByAccountIdAndCreatedAtIsAfter(int id, OffsetDateTime createdAt);
	
}
