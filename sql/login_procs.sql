DELIMITER $$

-- -----------------------------------------------
DROP FUNCTION IF EXISTS App_Email_Form_Is_Valid $$
CREATE FUNCTION App_Email_Form_Is_Valid(email VARCHAR(128))
   RETURNS BOOLEAN
BEGIN
   IF email IS NULL THEN
      RETURN FALSE;
   ELSE
      RETURN email REGEXP '[[:alnum:]][[:alnum:]-]+(\.[[:alnum:]][[:alnum:]-]+)*@[[:alnum:]][[:alnum:]-]+(\.[[:alnum:]][[:alnum:]-]+)+';
   END IF;

   -- RETURN email REGEXP '[[:alnum:]!#$%&\'*+-/=?^_`{|}~]+(\.[[:alnum:]!#$%&\'*+-/=?^_`{|}~]+)*@[[:alnum:]][[:alnum:]-])+(\.[[:alnum:]][[:alnum:]-])+';
END $$

-- ------------------------------------------
DROP PROCEDURE IF EXISTS App_Account_Login $$
CREATE PROCEDURE App_Account_Login(email VARCHAR(128),
                                   password VARCHAR(20))
BEGIN
   DECLARE user_id INT UNSIGNED;
   DECLARE account_id INT UNSIGNED;

   SELECT u.id, u.id_account INTO user_id, account_id
     FROM User u
          INNER JOIN Salt s ON u.id = s.id_user
    WHERE u.email = email
      AND u.pword_hash = ssys_hash_password_with_salt(password, s.salt);

   IF user_id IS NULL THEN
      SELECT 1 AS error, 'Email or password not recognized.' AS msg;
   ELSE
      SELECT 0 AS error, 'Logged in.' AS msg;

      -- This generated procedure resides in session_procs.sql:
      CALL App_Session_Initialize(account_id, user_id, email);
   END IF;   

END $$

-- -------------------------------------------
DROP PROCEDURE IF EXISTS App_Account_Create $$
CREATE PROCEDURE App_Account_Create(email VARCHAR(128),
                                    account_name VARCHAR(80),
                                    password VARCHAR(20))
proc_block: BEGIN
   DECLARE name_count INT UNSIGNED;
   DECLARE account_id INT UNSIGNED;
   DECLARE user_id INT UNSIGNED;

   -- Terminate processing if missing salt:
   IF @dropped_salt IS NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='No dropped_salt to encode the password.';
   END IF;

   -- Leave with error for invalid or missing parameters:
   IF NOT (App_Email_Form_Is_Valid(email)) THEN
      SELECT 2 AS error,
             CONCAT('The email address, ', email, ' is not valid.') AS msg;
      LEAVE proc_block;
   END IF;

   IF account_name IS NULL OR LENGTH(account_name) = 0 THEN
      SELECT 3 AS error, 'Missing account name' AS msg;
      LEAVE proc_block;
   END IF;

   IF password IS NULL OR LENGTH(password) = 0 THEN
      SELECT 3 AS error, 'Missing password' AS msg;
      LEAVE proc_block;
   END IF;

   -- Confirm unique account_name
   SELECT COUNT(*) INTO name_count
     FROM Account
    WHERE name = account_name;

   IF name_count > 0 THEN
      SELECT 1 AS error,
             CONCAT('The name ', account_name, ' is already in use.  Please try another name.') AS msg;
      LEAVE proc_block;
   END IF;

   -- Input validated, account creation may commence.
   INSERT INTO Account(name) VALUES(account_name);

   IF ROW_COUNT() > 0 THEN
      START TRANSACTION;

      SELECT LAST_INSERT_ID() INTO account_id;

      IF account_id IS NOT NULL THEN
         INSERT INTO User(id_account, user_type, email, pword_hash)
                VALUES(account_id,
                       'administrator',
                        email,
                        ssys_hash_password_with_salt(password, @dropped_salt));

         IF ROW_COUNT() > 0 THEN
            SELECT LAST_INSERT_ID() INTO user_id;
            IF user_id IS NOT NULL THEN
               INSERT INTO Salt(id_user, salt)
                      VALUES(user_id, @dropped_salt);

               IF ROW_COUNT() > 0 THEN
                  SELECT 0 AS error, 'Success' AS msg;
                  COMMIT;

                  -- This generated procedure resides in session_procs.sql:
                  CALL App_Session_Initialize(account_id, user_id, email);

                  LEAVE proc_block;
               END IF;
            END IF;
         END IF;
      END IF;

      ROLLBACK;

      SELECT 2 AS error,
             CONCAT('Failed to create account ', account_name, '. Please try again later.') AS msg;
   END IF;
   
END $$


DELIMITER ;
