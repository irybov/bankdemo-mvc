INSERT INTO bankdemo.accounts(id, is_active, birthday, name, password, phone, surname, created_at, updated_at)
VALUES('0', '1', '2001-01-01', 'Admin', crypt('superadmin', gen_salt('bf', 4)), '0000000000', 'Adminov', now(), now());
INSERT INTO bankdemo.accounts(is_active, birthday, name, password, phone, surname, created_at, updated_at)
VALUES('1', '1985-08-31', 'Kae', crypt('supervixen', gen_salt('bf', 4)), '1111111111', 'Yukawa', now(), now()),
('1', '1974-07-28', 'Hannah', crypt('bustyblonde', gen_salt('bf', 4)), '2222222222', 'Waddingham', now(), now()),
('1', '1995-06-13', 'Ella', crypt('gingerchick', gen_salt('bf', 4)), '3333333333', 'Hughes', now(), now())
ON CONFLICT ON CONSTRAINT accounts_phone_key DO NOTHING;

INSERT INTO bankdemo.roles(account_id, role) 
SELECT id, 'ADMIN' FROM bankdemo.accounts WHERE phone='0000000000'
UNION SELECT id, 'CLIENT' FROM bankdemo.accounts WHERE phone='1111111111'
UNION SELECT id, 'CLIENT' FROM bankdemo.accounts WHERE phone='2222222222'
UNION SELECT id, 'CLIENT' FROM bankdemo.accounts WHERE phone='3333333333'
UNION SELECT id, 'ADMIN' FROM bankdemo.accounts WHERE phone='3333333333';