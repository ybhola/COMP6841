<?php
include 'db.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Retrieve inputs
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Secure the SQL query using a prepared statement
    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");

    // Hash the password before storing it
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Bind parameters to the prepared statement
    $stmt->bind_param("ss", $username, $hashed_password);

    // Execute the query and check for success
    if ($stmt->execute()) {
        echo "User registered successfully!<br>";
        // Escape output to prevent XSS
        echo "Username: " . htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
    } else {
        // Log the error internally and show a generic message
        error_log("Database error: " . $conn->error);
        echo "An error occurred while registering the user. Please try again.";
    }

    // Close the prepared statement
    $stmt->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register</title>
</head>
<body>
    <h2>Register</h2>
    <form method="POST" action="">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <br>
        <input type="submit" value="Register">
    </form>
</body>
</html>
