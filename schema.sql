-- SQL Schema for Storify Store Database
-- You can copy and run this in phpMyAdmin SQL tab or import this file.

-- Note: In cloud database environments, the database is typically created for you.
-- If you need to create the database yourself, uncomment the next two lines:
-- CREATE DATABASE IF NOT EXISTS `storify_db` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- USE `storify_db`;

CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(100) NOT NULL UNIQUE,
    `phone` VARCHAR(25) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `address` VARCHAR(255) DEFAULT '',
    `city` VARCHAR(100) DEFAULT '',
    `zip` VARCHAR(20) DEFAULT '',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `reviews` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `product_id` INT NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(100) NOT NULL,
    `rating` INT NOT NULL,
    `comment` TEXT NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (`product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

