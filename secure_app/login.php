<?php
include 'db.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Secure the SQL query with prepared statements
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();

        // Verify the hashed password
        if (password_verify($password, $row['password'])) {
            // Escape the output to prevent XSS
            echo "<p>Welcome, " . htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8') . "!</p>";

            // Set a secure authentication cookie
            setcookie('auth', htmlspecialchars($username, ENT_QUOTES, 'UTF-8'), time() + 3600, "", "", true, true);
            header("Location: profile.php");
            exit();
        } else {
            echo "Invalid username or password.";
        }
    } else {
        echo "Invalid username or password.";
    }

    $stmt->close();
}

// Securely handle and escape the 'message' parameter to prevent XSS
if (isset($_GET['message'])) {
    echo "<p>Message: " . htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8') . "</p>";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    <form method="POST" action="">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
