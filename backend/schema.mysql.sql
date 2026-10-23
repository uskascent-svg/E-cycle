-- REFERENCE ONLY, NOT TESTED. A MySQL 8 / MariaDB translation of schema.sql for
-- the PHP/MySQL path mentioned in the original README. The running backend uses
-- SQLite (schema.sql). Differences: AUTO_INCREMENT, DATETIME, ENUM, utf8mb4.
CREATE TABLE users (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(254) NOT NULL UNIQUE,            -- utf8mb4_unicode_ci is case-insensitive
  phone VARCHAR(20) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,           -- PHP: password_hash() / password_verify()
  address VARCHAR(500) NOT NULL,
  role ENUM('user','admin') NOT NULL DEFAULT 'user',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE submissions (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  tracking_id VARCHAR(20) NOT NULL UNIQUE,
  user_id INT UNSIGNED NULL,
  category ENUM('Laptop','Mobile Phone','Television','Computer','Other') NOT NULL,
  device_name VARCHAR(100) NOT NULL,
  brand VARCHAR(100) NULL,
  quantity SMALLINT UNSIGNED NOT NULL,
  device_condition ENUM('working','partially_working','non_working') NOT NULL,
  battery_damaged TINYINT(1) NOT NULL DEFAULT 0,
  location VARCHAR(200) NOT NULL,
  description VARCHAR(1000) NULL,
  recommendation VARCHAR(50) NOT NULL,
  status ENUM('SUBMITTED','VERIFIED','COLLECTION_SCHEDULED','COLLECTED','PROCESSED') NOT NULL DEFAULT 'SUBMITTED',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT chk_qty CHECK (quantity BETWEEN 1 AND 1000),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_submissions_user (user_id), INDEX idx_submissions_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE status_history (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  submission_id INT UNSIGNED NOT NULL,
  status VARCHAR(30) NOT NULL,
  note VARCHAR(300) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE CASCADE,
  INDEX idx_history_submission (submission_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE drives (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(150) NOT NULL,
  location VARCHAR(200) NOT NULL,
  drive_date DATE NOT NULL,
  description VARCHAR(1000) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE drive_participants (
  drive_id INT UNSIGNED NOT NULL,
  user_id INT UNSIGNED NOT NULL,
  joined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (drive_id, user_id),
  FOREIGN KEY (drive_id) REFERENCES drives(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
