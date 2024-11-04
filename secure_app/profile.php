<!DOCTYPE html>
<html>
<head>
    <title>Profile</title>
</head>
<body>
    <h2>User Profile</h2>

    <?php
    include 'db.php';

    // Authentication Bypass Vulnerability
    if (!isset($_COOKIE['auth'])) {
        echo "<p>Not logged in! Please <a href='login.php'>login</a>.</p>";
        exit();
    }

    // Fetch user data based on username in cookie
    $username = $_COOKIE['auth'];
    $query = "SELECT * FROM users WHERE username = '$username'";
    $result = $conn->query($query);

    if ($result && $result->num_rows > 0) {
        $user = $result->fetch_assoc();
        echo "<p>Username: " . htmlspecialchars($user['username']) . "</p>";
        echo "<p>Welcome to your profile page, " . htmlspecialchars($user['username']) . ".</p>";
    } else {
        echo "<p>User not found.</p>";
    }
    ?>

    <a href="login.php">Logout</a>
</body>
</html>