INSERT INTO bankdemo.accounts(is_active, birthday, name, password, phone, surname, created_at, updated_at)
VALUES('1', '2001-01-01', 'Admin', 'superadmin', '0000000000', 'Adminov', now(), now());
INSERT INTO bankdemo.accounts(is_active, birthday, name, password, phone, surname, created_at, updated_at)
VALUES('1', '1985-08-31', 'Kae', 'supervixen', '1111111111', 'Yukawa', now(), now()),
('1', '1974-07-28', 'Hannah', 'bustyblonde', '2222222222', 'Waddingham', now(), now()),
('1', '1995-06-13', 'Ella', 'gingerchick', '3333333333', 'Hughes', now(), now())
ON CONFLICT DO NOTHING;
INSERT INTO bankdemo.roles(account_id, role) SELECT id, 'ADMIN' FROM bankdemo.accounts WHERE phone='0000000000'
UNION SELECT id, 'CLIENT' FROM bankdemo.accounts WHERE phone='1111111111'
UNION SELECT id, 'CLIENT' FROM bankdemo.accounts WHERE phone='2222222222'
UNION SELECT id, 'CLIENT' FROM bankdemo.accounts WHERE phone='3333333333'
UNION SELECT id, 'ADMIN' FROM bankdemo.accounts WHERE phone='3333333333';

INSERT INTO bankdemo.bills(id, is_active, balance, currency, account_id, created_at)
VALUES('1', '1', '10.00', 'USD', '1', now()), ('3', '1', '10.00', 'NOK', '3', now());

--UPDATE bankdemo.accounts SET password = HASH('SHA256', password, 4);