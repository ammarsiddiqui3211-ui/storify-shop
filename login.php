<?php
/**
 * Storify Store - PHP Authentication Endpoint
 * 
 * Auto-creates the 'storify_db' database and 'users' table if they do not exist.
 * Handles AJAX requests for:
 *   - register (Sign Up)
 *   - login (Sign In)
 *   - update_profile (Edit Details)
 */

// Enable error reporting for debugging, but prevent HTML error output in production-like JSON responses
error_reporting(E_ALL);
ini_set('display_errors', 0);

// Set headers for CORS and JSON response
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Content-Type: application/json; charset=UTF-8");

// Handle preflight OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Load environment variables from .env file if it exists
function loadEnv($dir) {
    $path = $dir . '/.env';
    if (!file_exists($path)) {
        return;
    }
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, '#') === 0) {
            continue;
        }
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) {
            $key = trim($parts[0]);
            $val = trim($parts[1]);
            // Strip quotes if present
            if ((strpos($val, '"') === 0 && strrpos($val, '"') === strlen($val) - 1) ||
                (strpos($val, "'") === 0 && strrpos($val, "'") === strlen($val) - 1)) {
                $val = substr($val, 1, -1);
            }
            putenv(sprintf('%s=%s', $key, $val));
            $_ENV[$key] = $val;
            $_SERVER[$key] = $val;
        }
    }
}
loadEnv(__DIR__);

// Database config parameters
$db_host = getenv('DB_HOST') !== false ? getenv('DB_HOST') : "localhost";
$db_user = getenv('DB_USER') !== false ? getenv('DB_USER') : "root";
$db_pass = getenv('DB_PASS') !== false ? getenv('DB_PASS') : "";
$db_name = getenv('DB_NAME') !== false ? getenv('DB_NAME') : "storify_db";

// 1. Establish connection to MySQL server and select the database directly
$conn = @new mysqli($db_host, $db_user, $db_pass, $db_name);

// If the database selection failed because the database does not exist, try to create it (e.g. on local localhost)
if ($conn->connect_errno === 1049) {
    $conn = @new mysqli($db_host, $db_user, $db_pass);
    if ($conn->connect_error) {
        echo json_encode([
            "success" => false,
            "message" => "Database connection failed. Please ensure MySQL is running: " . $conn->connect_error
        ]);
        exit();
    }
    // Attempt to create database (will succeed on local MySQL, but may be restricted on cloud hosts where db is pre-created)
    if ($conn->query("CREATE DATABASE IF NOT EXISTS `$db_name` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")) {
        $conn->select_db($db_name);
    } else {
        echo json_encode([
            "success" => false,
            "message" => "Failed to select or create database: " . $conn->error
        ]);
        $conn->close();
        exit();
    }
} elseif ($conn->connect_error) {
    echo json_encode([
        "success" => false,
        "message" => "Database connection failed: " . $conn->connect_error
    ]);
    exit();
}

// 4. Auto-create 'users' table if not exists
$table_sql = "CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(100) NOT NULL UNIQUE,
    `phone` VARCHAR(25) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `address` VARCHAR(255) DEFAULT '',
    `city` VARCHAR(100) DEFAULT '',
    `zip` VARCHAR(20) DEFAULT '',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

if (!$conn->query($table_sql)) {
    echo json_encode([
        "success" => false,
        "message" => "Failed to initialize tables: " . $conn->error
    ]);
    $conn->close();
    exit();
}

// 5. Auto-create 'reviews' table if not exists
$reviews_table_sql = "CREATE TABLE IF NOT EXISTS `reviews` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `product_id` INT NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(100) NOT NULL,
    `rating` INT NOT NULL,
    `comment` TEXT NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (`product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

if (!$conn->query($reviews_table_sql)) {
    echo json_encode([
        "success" => false,
        "message" => "Failed to initialize reviews table: " . $conn->error
    ]);
    $conn->close();
    exit();
}

// Parse request payload
$raw_input = file_get_contents('php://input');
$input = json_decode($raw_input, true);

// Fallback to normal $_POST if JSON decode is empty
if (!$input) {
    $input = $_POST;
}

$action = isset($input['action']) ? trim($input['action']) : '';

if (!$action) {
    echo json_encode([
        "success" => false,
        "message" => "Invalid action or endpoint requested."
    ]);
    $conn->close();
    exit();
}

// ROUTE THE ACTION
switch ($action) {
    case 'register':
        handleRegister($conn, $input);
        break;
        
    case 'login':
        handleLogin($conn, $input);
        break;
        
    case 'update_profile':
        handleUpdateProfile($conn, $input);
        break;

    case 'get_reviews':
        handleGetReviews($conn, $input);
        break;

    case 'add_review':
        handleAddReview($conn, $input);
        break;

    case 'get_all_review_stats':
        handleGetAllReviewStats($conn);
        break;
        
    default:
        echo json_encode([
            "success" => false,
            "message" => "Action '$action' not recognized."
        ]);
        break;
}

$conn->close();
exit();

// --- HELPER HANDLER FUNCTIONS ---

/**
 * Handle user registration
 */
function handleRegister($conn, $data) {
    $name = isset($data['name']) ? trim($data['name']) : '';
    $email = isset($data['email']) ? trim($data['email']) : '';
    $phone = isset($data['phone']) ? trim($data['phone']) : '';
    $password = isset($data['password']) ? $data['password'] : '';

    // Validate inputs
    if (empty($name) || empty($email) || empty($phone) || empty($password)) {
        echo json_encode([
            "success" => false,
            "message" => "Name, Email, Phone, and Password are required."
        ]);
        return;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode([
            "success" => false,
            "message" => "Please enter a valid email address."
        ]);
        return;
    }

    if (strlen($password) < 6) {
        echo json_encode([
            "success" => false,
            "message" => "Password must be at least 6 characters long."
        ]);
        return;
    }

    // Check if email already registered
    $check_stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $check_stmt->bind_param("s", $email);
    $check_stmt->execute();
    $check_stmt->store_result();
    
    if ($check_stmt->num_rows > 0) {
        echo json_encode([
            "success" => false,
            "message" => "This email address is already registered. Please login instead."
        ]);
        $check_stmt->close();
        return;
    }
    $check_stmt->close();

    // Securely hash password
    $hashed_pass = password_hash($password, PASSWORD_DEFAULT);

    // Insert user record - omitting address, city, zip so they fall back to DB defaults ('')
    $stmt = $conn->prepare("INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $name, $email, $phone, $hashed_pass);

    if ($stmt->execute()) {
        // Fetch saved user data (excluding password)
        $user_id = $conn->insert_id;
        echo json_encode([
            "success" => true,
            "message" => "Account successfully created!",
            "user" => [
                "id" => $user_id,
                "name" => $name,
                "email" => $email,
                "phone" => $phone,
                "address" => "",
                "city" => "",
                "zip" => ""
            ]
        ]);
    } else {
        echo json_encode([
            "success" => false,
            "message" => "Registration failed: " . $stmt->error
        ]);
    }
    $stmt->close();
}

/**
 * Handle user login verification
 */
function handleLogin($conn, $data) {
    $email = isset($data['email']) ? trim($data['email']) : '';
    $password = isset($data['password']) ? $data['password'] : '';

    if (empty($email) || empty($password)) {
        echo json_encode([
            "success" => false,
            "message" => "Email and Password are required."
        ]);
        return;
    }

    // Fetch user details
    $stmt = $conn->prepare("SELECT id, name, email, phone, password, address, city, zip FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        echo json_encode([
            "success" => false,
            "message" => "No account found with this email address."
        ]);
        $stmt->close();
        return;
    }

    $user = $result->fetch_assoc();
    $stmt->close();

    // Verify Password hash
    if (password_verify($password, $user['password'])) {
        echo json_encode([
            "success" => true,
            "message" => "Welcome back!",
            "user" => [
                "id" => $user['id'],
                "name" => $user['name'],
                "email" => $user['email'],
                "phone" => $user['phone'],
                "address" => $user['address'],
                "city" => $user['city'],
                "zip" => $user['zip']
            ]
        ]);
    } else {
        echo json_encode([
            "success" => false,
            "message" => "Incorrect password. Please try again."
        ]);
    }
}

/**
 * Handle updating profile details
 */
function handleUpdateProfile($conn, $data) {
    $name = isset($data['name']) ? trim($data['name']) : '';
    $email = isset($data['email']) ? trim($data['email']) : '';
    $phone = isset($data['phone']) ? trim($data['phone']) : '';
    $address = isset($data['address']) ? trim($data['address']) : '';
    $city = isset($data['city']) ? trim($data['city']) : '';
    $zip = isset($data['zip']) ? trim($data['zip']) : '';

    if (empty($email) || empty($name) || empty($phone)) {
        echo json_encode([
            "success" => false,
            "message" => "Name, Email, and Phone are required."
        ]);
        return;
    }

    // Update details in database
    $stmt = $conn->prepare("UPDATE users SET name = ?, phone = ?, address = ?, city = ?, zip = ? WHERE email = ?");
    $stmt->bind_param("ssssss", $name, $phone, $address, $city, $zip, $email);

    if ($stmt->execute()) {
        echo json_encode([
            "success" => true,
            "message" => "Profile successfully updated!",
            "user" => [
                "name" => $name,
                "email" => $email,
                "phone" => $phone,
                "address" => $address,
                "city" => $city,
                "zip" => $zip
            ]
        ]);
    } else {
        echo json_encode([
            "success" => false,
            "message" => "Failed to update profile: " . $stmt->error
        ]);
    }
    $stmt->close();
}

/**
 * Handle fetching reviews for a product
 */
function handleGetReviews($conn, $data) {
    $product_id = isset($data['product_id']) ? intval($data['product_id']) : 0;

    if ($product_id <= 0) {
        echo json_encode([
            "success" => false,
            "message" => "Invalid product ID."
        ]);
        return;
    }

    $stmt = $conn->prepare("SELECT id, name, rating, comment, created_at FROM reviews WHERE product_id = ? ORDER BY created_at DESC");
    $stmt->bind_param("i", $product_id);
    $stmt->execute();
    $result = $stmt->get_result();

    $reviews = [];
    while ($row = $result->fetch_assoc()) {
        $reviews[] = [
            "id" => intval($row['id']),
            "name" => $row['name'],
            "rating" => intval($row['rating']),
            "comment" => $row['comment'],
            "created_at" => $row['created_at']
        ];
    }
    $stmt->close();

    echo json_encode([
        "success" => true,
        "reviews" => $reviews
    ]);
}

/**
 * Handle adding a new review for a product
 */
function handleAddReview($conn, $data) {
    $product_id = isset($data['product_id']) ? intval($data['product_id']) : 0;
    $name = isset($data['name']) ? trim($data['name']) : '';
    $email = isset($data['email']) ? trim($data['email']) : '';
    $rating = isset($data['rating']) ? intval($data['rating']) : 0;
    $comment = isset($data['comment']) ? trim($data['comment']) : '';

    if ($product_id <= 0 || empty($name) || empty($email) || $rating < 1 || $rating > 5 || empty($comment)) {
        echo json_encode([
            "success" => false,
            "message" => "Please complete all required fields and provide a valid rating (1-5)."
        ]);
        return;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode([
            "success" => false,
            "message" => "Please enter a valid email address."
        ]);
        return;
    }

    $stmt = $conn->prepare("INSERT INTO reviews (product_id, name, email, rating, comment) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("issis", $product_id, $name, $email, $rating, $comment);

    if ($stmt->execute()) {
        echo json_encode([
            "success" => true,
            "message" => "Thank you! Your review has been submitted."
        ]);
    } else {
        echo json_encode([
            "success" => false,
            "message" => "Failed to submit review: " . $stmt->error
        ]);
    }
    $stmt->close();
}

/**
 * Fetch review count and average rating aggregates grouped by product ID
 */
function handleGetAllReviewStats($conn) {
    $result = $conn->query("SELECT product_id, COUNT(*) as count, AVG(rating) as avg_rating FROM reviews GROUP BY product_id");
    $stats = [];
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $stats[] = [
                "product_id" => intval($row['product_id']),
                "count" => intval($row['count']),
                "avg_rating" => floatval($row['avg_rating'])
            ];
        }
    }
    echo json_encode([
        "success" => true,
        "stats" => $stats
    ]);
}
?>
