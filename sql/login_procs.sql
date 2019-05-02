DELIMITER $$

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

   SELECT COUNT(*) INTO name_count
     FROM Account
    WHERE name = account_name;

   IF name_count > 0 THEN
      SELECT 1 AS error,
             CONCAT('The name ', account_name, ' is already in use.  Please try another name.') AS msg;
      LEAVE proc_block;
   END IF;

   -- Account creation commences here:
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
