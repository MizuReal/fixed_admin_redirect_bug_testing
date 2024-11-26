<?php
//This is for checking if the account has been deleted or not.
// Check if the session is already started
if (session_status() == PHP_SESSION_NONE) {
    session_start(); // Start the session if not already started
}
include('../server/connection.php');
function validate_admin_session() {
    // Check if admin is logged in
    if (!isset($_SESSION['admin_logged_in']) || !$_SESSION['admin_logged_in']) {
        header('location: login.php?error=Please log in');
        exit;
    }

    // Additional database check to verify account still exists
    global $conn; // Assuming database connection is global or passed correctly

    // Prepare statement to check if admin account still exists
    $stmt = $conn->prepare("SELECT admin_id FROM admins WHERE admin_id = ?");
    
    // Use the stored admin_id to check
    $stmt->bind_param('i', $_SESSION['admin_id']);
    $stmt->execute();
    $stmt->store_result();

    // If no rows found, the admin account has been deleted
    if ($stmt->num_rows == 0) {
        // Destroy the session
        session_unset();
        session_destroy();
        
        // Redirect to login page
        header('location: login.php?error=Your account has been deleted');
        exit;
    }

    $stmt->close();
}
?>