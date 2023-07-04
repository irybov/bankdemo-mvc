CREATE SCHEMA IF NOT EXISTS bankdemo;
CREATE TABLE IF NOT EXISTS bankdemo.accounts(
  id INTEGER PRIMARY KEY AUTO_INCREMENT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  is_active BOOLEAN NOT NULL,
  name VARCHAR(20) NOT NULL,
  surname VARCHAR(40) NOT NULL,
  phone VARCHAR(10) UNIQUE NOT NULL CHECK (CHAR_LENGTH(phone) = 10),
  birthday DATE NOT NULL,
  password VARCHAR(60) NOT NULL
);
CREATE TABLE IF NOT EXISTS bankdemo.bills(
  id INTEGER PRIMARY KEY AUTO_INCREMENT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  is_active BOOLEAN NOT NULL,
  balance NUMERIC(19,2) NOT NULL,
  currency VARCHAR(3) NOT NULL CHECK (CHAR_LENGTH(currency) = 3),
  account_id INTEGER,
  FOREIGN KEY(account_id) REFERENCES bankdemo.accounts(id)
);
CREATE TABLE IF NOT EXISTS bankdemo.operations(
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  created_at TIMESTAMP NOT NULL,
  amount DOUBLE PRECISION NOT NULL,
  action VARCHAR(10) NOT NULL,
  currency VARCHAR(3) NOT NULL CHECK (CHAR_LENGTH(currency) = 3),
  sender INTEGER,
  recipient INTEGER,
  bank VARCHAR(30) NOT NULL
);
CREATE TABLE IF NOT EXISTS bankdemo.roles(
  roles VARCHAR(10) NOT NULL,
  account_id INTEGER NOT NULL,
  FOREIGN KEY(account_id) REFERENCES bankdemo.accounts(id)
);