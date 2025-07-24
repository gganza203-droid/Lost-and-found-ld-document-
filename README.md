<?php
// index.php

// 🔌 DATABASE CONNECTION
$host = 'localhost';
$db = 'lost_and_found';
$user = 'root';
$pass = '';
try {
    $pdo = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// 🟡 SESSION MANAGEMENT
session_start();
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}
function requireLogin() {
    if (!isLoggedIn()) {
        die("Access denied. Please log in.");
    }
}

// 📧 SIMPLE EMAIL SENDER
function sendNotification($to, $subject, $message) {
    $headers = "From: notify@yourdomain.com\r\n";
    $headers .= "Content-type: text/plain; charset=UTF-8\r\n";
    return mail($to, $subject, $message, $headers);
}

// ✍️ REGISTER
if (isset($_POST['register'])) {
    $name = $_POST['name'];
    $email = $_POST['email'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
    $role = $_POST['role']; // 'user' or 'organization'

    $stmt = $pdo->prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)");
    $stmt->execute([$name, $email, $password, $role]);

    echo "<p>✅ Registration successful.</p>";
}

// 🔐 LOGIN
if (isset($_POST['login'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];

    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['role'] = $user['role'];
        echo "<p>✅ Login successful.</p>";
    } else {
        echo "<p>❌ Invalid credentials.</p>";
    }
}

// 📥 REPORT LOST ID
if (isset($_POST['report_lost'])) {
    requireLogin();
    $user_id = $_SESSION['user_id'];
    $id_type = $_POST['id_type'];
    $id_number = $_POST['id_number'];
    $full_name = $_POST['full_name'];

    $stmt = $pdo->prepare("INSERT INTO lost_ids (user_id, id_type, id_number, full_name) VALUES (?, ?, ?, ?)");
    $stmt->execute([$user_id, $id_type, $id_number, $full_name]);

    echo "<p>✅ Lost ID reported.</p>";
}

// 📤 REPORT FOUND ID
if (isset($_POST['report_found'])) {
    requireLogin();
    if ($_SESSION['role'] != 'organization') {
        die("<p>❌ Only organizations can report found IDs.</p>");
    }
    $org_id = $_SESSION['user_id'];
    $id_type = $_POST['id_type'];
    $id_number = $_POST['id_number'];
    $full_name = $_POST['full_name'];

    $stmt = $pdo->prepare("INSERT INTO found_ids (org_id, id_type, id_number, full_name) VALUES (?, ?, ?, ?)");
    $stmt->execute([$org_id, $id_type, $id_number, $full_name]);

    echo "<p>✅ Found ID reported.</p>";
}

// 🔁 MATCH ENGINE
if (isset($_GET['match_engine'])) {
    $sql = "SELECT l.id AS lost_id, f.id AS found_id, l.user_id, u.email
            FROM lost_ids l
            JOIN found_ids f ON l.id_type = f.id_type AND l.id_number = f.id_number
            JOIN users u ON l.user_id = u.id
            WHERE l.matched = 0 AND f.matched = 0";

    foreach ($pdo->query($sql) as $row) {
        $pdo->prepare("UPDATE lost_ids SET matched = 1 WHERE id = ?")->execute([$row['lost_id']]);
        $pdo->prepare("UPDATE found_ids SET matched = 1 WHERE id = ?")->execute([$row['found_id']]);

        sendNotification($row['email'], "We found your lost ID", "Hello, your lost ID has been found! Please check our system.");
    }
    echo "<p>✅ Match engine completed.</p>";
}

// 🔍 SEARCH
$searchResults = "";
if (isset($_GET['search'])) {
    $query = $_GET['search'];
    $stmt = $pdo->prepare("SELECT * FROM found_ids WHERE id_number LIKE ?");
    $stmt->execute(["%$query%"]);
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $searchResults = "<h3>🔍 Search Results:</h3><ul>";
    foreach ($results as $row) {
        $searchResults .= "<li>{$row['id_type']} - {$row['id_number']} - {$row['full_name']}</li>";
    }
    $searchResults .= "</ul>";
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Lost and Found ID System</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f8f8f8; }
        form { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 0 5px #ccc; }
        h2 { color: #333; }
    </style>
</head>
<body>

<h1>🔐 Lost and Found ID Matching System</h1>

<h2>Register</h2>
<form method="POST">
    <input name="name" placeholder="Full Name" required><br>
    <input name="email" type="email" placeholder="Email" required><br>
    <input name="password" type="password" placeholder="Password" required><br>
    <select name="role" required>
        <option value="user">User</option>
        <option value="organization">Organization</option>
    </select><br><br>
    <button name="register">Register</button>
</form>

<h2>Login</h2>
<form method="POST">
    <input name="email" type="email" placeholder="Email" required><br>
    <input name="password" type="password" placeholder="Password" required><br><br>
    <button name="login">Login</button>
</form>

<h2>Report Lost ID (User)</h2>
<form method="POST">
    <input name="id_type" placeholder="ID Type (e.g., National ID)" required><br>
    <input name="id_number" placeholder="ID Number" required><br>
    <input name="full_name" placeholder="Full Name on ID" required><br><br>
    <button name="report_lost">Report Lost</button>
</form>

<h2>Report Found ID (Organization)</h2>
<form method="POST">
    <input name="id_type" placeholder="ID Type (e.g., Passport)" required><br>
    <input name="id_number" placeholder="ID Number" required><br>
    <input name="full_name" placeholder="Full Name on ID" required><br><br>
    <button name="report_found">Report Found</button>
</form>

<h2>Search Found IDs</h2>
<form method="GET">
    <input name="search" placeholder="Enter ID Number">
    <button>Search</button>
</form>

<?php echo $searchResults; ?>

<h2>Match Engine (for Admin or Cron)</h2>
<form method="GET">
    <button name="match_engine" value="1">Run Match Engine</button>
</form>

</body>
</html>
