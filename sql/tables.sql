USE SFW_INVITE;

CREATE TABLE IF NOT EXISTS Account
(
   id    INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
   name  VARCHAR(80)
);

CREATE TABLE IF NOT EXISTS User
(
   id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
   id_account INT UNSIGNED NOT NULL,
   user_type  ENUM('administrator','user'),
   email      VARCHAR(128),
   pword_hash BINARY(16),
   handle     VARCHAR(32),

   INDEX(id_account),
   INDEX(email)
);

CREATE TABLE IF NOT EXISTS Salt
(
   id_user   INT UNSIGNED NOT NULL PRIMARY KEY,
   salt      CHAR(32)
);

CREATE TABLE IF NOT EXISTS Invitation
(
   id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
   id_account INT UNSIGNED NOT NULL,
   email      VARCHAR(128),
   expires    DATETIME,

   INDEX(id_account)
);
