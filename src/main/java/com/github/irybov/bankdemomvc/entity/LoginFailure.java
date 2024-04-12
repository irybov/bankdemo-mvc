package com.github.irybov.bankdemomvc.entity;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@Getter
@Entity
@DiscriminatorValue(value = "failure")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class LoginFailure extends Login {

}
