package com.github.irybov.bankdemomvc.entity;

import java.time.OffsetDateTime;

import javax.persistence.Column;
import javax.persistence.DiscriminatorColumn;
import javax.persistence.DiscriminatorType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
//import javax.persistence.MappedSuperclass;
import javax.persistence.Table;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;


@SuperBuilder
@Getter
@Entity
//@MappedSuperclass
@Table(name="logins", schema = "bankdemo")
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name = "event", discriminatorType = DiscriminatorType.STRING)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class Login {

	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(updatable = false)
	private Long id;
	
	@Column(nullable = false, updatable = false)
	private OffsetDateTime createdAt;
	
	@Column(nullable = false, updatable = false)
	private String sourceIp;
	
    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name="account_id", nullable = false, updatable = false)
	private Account account;
    
    @Column(insertable = false, nullable = false, updatable = false)
    private String event;
	
}
