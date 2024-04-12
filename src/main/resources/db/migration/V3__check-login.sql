CREATE TABLE IF NOT EXISTS bankdemo.logins(
	id BIGSERIAL PRIMARY KEY,
	created_at TIMESTAMP NOT NULL,
	source_ip VARCHAR(40) NOT NULL,
	event VARCHAR(10) NOT NULL,
	account_id INTEGER REFERENCES bankdemo.accounts(id) NOT NULL	
)