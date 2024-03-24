package com.github.irybov.bankdemomvc.controller.dto;

import java.time.LocalDate;
import java.time.OffsetDateTime;
//import java.util.Collection;
import java.util.List;
//import java.util.Set;
//import java.util.stream.Collectors;

import org.springframework.format.annotation.DateTimeFormat;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.github.irybov.bankdemomvc.entity.Account;

import io.swagger.annotations.ApiModel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@ApiModel
@Getter
@Setter
@NoArgsConstructor
public class AccountResponse {
	
	private Integer id;
	private OffsetDateTime createdAt;
	private OffsetDateTime updatedAt;	
	private boolean active;	
	private String name;	
	private String surname;
	private String phone;
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
	@DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
	private LocalDate birthday;
//	private String password;
	@JsonManagedReference
	private List<BillResponse> bills;
//	private Set<Role> roles;

/*	public AccountResponse(Account account) {
		
		this.id = account.getId();
		this.createdAt = account.getCreatedAt();
		this.updatedAt = account.getUpdatedAt();
		this.active = account.isActive();
		this.name = account.getName();
		this.surname = account.getSurname();
		this.phone = account.getPhone();
		this.birthday = account.getBirthday();
//		this.password = account.getPassword();
		this.bills = account.getBills()
				.stream()
//				.filter(Bill::isActive)
				.map(BillResponseDTO::new)
				.collect(Collectors.toList());
//		this.roles = account.getRoles();
	}*/	
	public void setBills(List<BillResponse> bills) {
		this.bills = bills;
	}
	
}
