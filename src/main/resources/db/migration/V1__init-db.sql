CREATE SCHEMA IF NOT EXISTS bankdemo;
CREATE TABLE IF NOT EXISTS bankdemo.accounts(
	id SERIAL PRIMARY KEY,
	created_at TIMESTAMP,
	updated_at TIMESTAMP,
	is_active BOOLEAN NOT NULL,
	name VARCHAR(20) NOT NULL,
	surname VARCHAR(40) NOT NULL,
	phone VARCHAR(10) UNIQUE NOT NULL CONSTRAINT phonechk CHECK (CHAR_LENGTH(phone) = 10),
	birthday DATE NOT NULL,
	password VARCHAR(60) NOT NULL
);
CREATE TABLE IF NOT EXISTS bankdemo.bills(
	id SERIAL PRIMARY KEY,
	created_at TIMESTAMP,
	updated_at TIMESTAMP,
	is_active BOOLEAN NOT NULL,
	balance NUMERIC(19,2) NOT NULL,
	currency VARCHAR(3) NOT NULL CONSTRAINT currencychk CHECK (CHAR_LENGTH(currency) = 3),
	account_id INTEGER REFERENCES bankdemo.accounts(id) NOT NULL
);
CREATE TABLE IF NOT EXISTS bankdemo.operations(
	id BIGSERIAL PRIMARY KEY,
	created_at TIMESTAMP NOT NULL,
	amount DOUBLE PRECISION NOT NULL,
	action VARCHAR(10) NOT NULL,
	currency VARCHAR(3) NOT NULL CONSTRAINT currencychk CHECK (CHAR_LENGTH(currency) = 3),
	sender INTEGER,
	recipient INTEGER,
	bank VARCHAR(30) NOT NULL
);
CREATE TABLE IF NOT EXISTS bankdemo.roles(
	role VARCHAR(10) NOT NULL,
	account_id INTEGER REFERENCES bankdemo.accounts(id) NOT NULL
);
CREATE EXTENSION IF NOT EXISTS pgcrypto;