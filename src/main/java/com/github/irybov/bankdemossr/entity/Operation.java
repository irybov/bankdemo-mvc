package com.github.irybov.bankdemossr.entity;

import java.time.OffsetDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Builder
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Table(name="operations", schema = "bankdemo")
@ToString
public class Operation {

	@EqualsAndHashCode.Exclude
	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(updatable = false)
	private Long id;
	
//	@Builder.Default
	@Column(updatable = false)
	private OffsetDateTime createdAt;
	
	@Column(nullable = false, updatable = false)
	private Double amount;

	@Column(nullable = false, updatable = false)
	private String action;
	
	@Column(nullable = false, length=3, updatable = false)
	private String currency;
	
	@Column(updatable = false)
	private Integer sender;
	@Column(updatable = false)
	private Integer recipient;
	
	@Column(nullable = false, updatable = false)
	private String bank;
	
}
