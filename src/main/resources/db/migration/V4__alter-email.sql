ALTER TABLE bankdemo.accounts ADD COLUMN email VARCHAR(60) UNIQUE;

--UPDATE bankdemo.accounts 
--SET email = CONCAT((SELECT LOWER(surname) FROM bankdemo.accounts WHERE phone='0000000000'), '@greenmail.io') WHERE phone='0000000000';
--UPDATE bankdemo.accounts 
--SET email = CONCAT((SELECT LOWER(surname) FROM bankdemo.accounts WHERE phone='1111111111'), '@greenmail.io') WHERE phone='1111111111';
--UPDATE bankdemo.accounts 
--SET email = CONCAT((SELECT LOWER(surname) FROM bankdemo.accounts WHERE phone='2222222222'), '@greenmail.io') WHERE phone='2222222222';
--UPDATE bankdemo.accounts 
--SET email = CONCAT((SELECT LOWER(surname) FROM bankdemo.accounts WHERE phone='3333333333'), '@greenmail.io') WHERE phone='3333333333';

UPDATE bankdemo.accounts SET email = 
CASE 
WHEN phone='0000000000' THEN CONCAT((SELECT LOWER(surname) FROM bankdemo.accounts WHERE phone='0000000000'), '@greenmail.io')
WHEN phone='1111111111' THEN CONCAT((SELECT LOWER(surname) FROM bankdemo.accounts WHERE phone='1111111111'), '@greenmail.io')
WHEN phone='2222222222' THEN CONCAT((SELECT LOWER(surname) FROM bankdemo.accounts WHERE phone='2222222222'), '@greenmail.io')
WHEN phone='3333333333' THEN CONCAT((SELECT LOWER(surname) FROM bankdemo.accounts WHERE phone='3333333333'), '@greenmail.io')
END;
--WHERE phone IN('0000000000', '1111111111', '2222222222', '3333333333');

ALTER TABLE bankdemo.accounts ALTER COLUMN email SET NOT NULL;