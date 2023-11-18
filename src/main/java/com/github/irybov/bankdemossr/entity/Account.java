package com.github.irybov.bankdemossr.entity;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;

import com.github.irybov.bankdemossr.security.Role;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.EqualsAndHashCode.CacheStrategy;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Table(name="accounts", schema = "bankdemo",
uniqueConstraints={@UniqueConstraint(columnNames={"phone"})})
@Data
@NoArgsConstructor
@EqualsAndHashCode(of = "phone", cacheStrategy=CacheStrategy.LAZY)
public class Account{

//	@EqualsAndHashCode.Exclude
	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(updatable = false)
	private Integer id;

//	@EqualsAndHashCode.Exclude
	@ToString.Exclude
	@Column(updatable = false)
	private OffsetDateTime createdAt;
	
//	@EqualsAndHashCode.Exclude
	@ToString.Exclude
	private OffsetDateTime updatedAt;
	
	@Column(nullable = false)
	private boolean isActive;
	
	@Column(nullable = false, length=20)
	private String name;
	
	@Column(nullable = false, length=40)
	private String surname;
	
	@Column(unique=true, nullable = false, length=10)
	private String phone;
	
	@Column(columnDefinition = "date")
	private LocalDate birthday;
	
	@Column(nullable = false, length=60)
	private String password;
	
//	@EqualsAndHashCode.Exclude
	@ToString.Exclude
	@OneToMany(mappedBy="owner", cascade = CascadeType.ALL, fetch=FetchType.LAZY)
//	@JoinColumn(name="account_id")
	private List<Bill> bills;

//	@EqualsAndHashCode.Exclude
	@ToString.Exclude
	@ElementCollection(targetClass = Role.class, fetch=FetchType.EAGER)
	@CollectionTable(name="roles", joinColumns = @JoinColumn(name="account_id"))
	@Enumerated(EnumType.STRING)
	@Column(name = "role")
	private Set<Role> roles;
	
	public Account(String name, String surname, String phone, LocalDate birthday, String password,
			boolean isActive) {
		this.name = name;
		this.surname = surname;
		this.phone = phone;
		this.birthday = birthday;
		this.password = password;
		this.isActive = isActive;
	}	
	
	public void addBill(Bill bill) {
		if(bills == null) {
			bills = new ArrayList<>();
		}
		bills.add(bill);
		bill.setOwner(this);
	}

	public void addRole(Role role) {
		if(roles == null) {
			roles = new HashSet<>();
		}
		roles.add(role);
	}
	
	@PrePersist
	protected void onCreate() {
		createdAt = OffsetDateTime.now();
	}
	@PreUpdate
	protected void onUpdate() {
		updatedAt = OffsetDateTime.now();
	}

}
