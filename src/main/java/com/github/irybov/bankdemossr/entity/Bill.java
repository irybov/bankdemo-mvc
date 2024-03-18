package com.github.irybov.bankdemossr.entity;

import java.math.BigDecimal;
import java.time.OffsetDateTime;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Entity
@Table(name="bills", schema = "bankdemo")
@Data
@NoArgsConstructor
public class Bill {

	@EqualsAndHashCode.Exclude
	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(updatable = false)
	private Integer id;

	@Column(updatable = false)
	private OffsetDateTime createdAt;
	
	private OffsetDateTime updatedAt;
	
	@Column(nullable = false)
	private boolean isActive;
	
	@Column(nullable = false, columnDefinition = "Decimal(19,2) default '0.00'", scale = 2, precision = 2)
	private BigDecimal balance = BigDecimal.valueOf(0.00).setScale(2);

	@Column(nullable = false, length=3, updatable = false)
	private String currency;
	
	@ManyToOne(cascade = {CascadeType.MERGE, CascadeType.DETACH, CascadeType.REFRESH}, 
			fetch=FetchType.EAGER)
	@JoinColumn(name="account_id", nullable = false, updatable = false)
	private Account owner;
	
	public Bill(String currency, boolean isActive, Account owner) {		
		this.currency = currency;
		this.isActive = isActive;
		this.owner = owner;
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
