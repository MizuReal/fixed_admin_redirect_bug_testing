<?php
include_once('../admin/validate_admin.php');
validate_admin_session();
// Check if admin is logged in
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    // Redirect to login page if not logged in
    header('location: login.php?error=Please login first');
    exit;
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Account</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style.css"> <!-- Link to external CSS -->
</head>
<body>
    <div class="dashboard">
        <!-- Sidebar -->
        <?php include('sidemenu.php'); ?>

        <!-- Main Content -->
        <div class="main-content">
            <!-- Header -->
            <?php include('header.php'); ?>
            <!-- Account Info Section -->
            <div class="account-info">
                <h2>Admin Account Information</h2>
                <div class="account-details">
                    <p><strong>ID:</strong> <?php echo htmlspecialchars($admin_id); ?></p>
                    <p><strong>Name:</strong> <?php echo htmlspecialchars($admin_name); ?></p>
                    <p><strong>Email:</strong> <?php echo htmlspecialchars($admin_email); ?></p>
                </div>

                <div class="account-actions">
                    <a href="update_account.php" class="btn update-btn">Update Account</a>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
