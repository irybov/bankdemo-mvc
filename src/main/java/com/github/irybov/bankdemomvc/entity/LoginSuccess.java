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
@DiscriminatorValue(value = "success")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class LoginSuccess extends Login {

}
