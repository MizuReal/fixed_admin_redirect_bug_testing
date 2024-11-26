<?php
session_start();
include('../server/connection.php');

// Validation function
function validate_input($input, $type) {
    $input = trim($input);

    switch($type) {
        case 'email':
            // Regex for email validation 
            // Allows standard email formats, including some less common but valid formats
            $email_regex = '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/';
            return preg_match($email_regex, $input) === 1;

        case 'password':
            // Regex for password validation
            // Requires:
            // - At least 8 characters
            // - At least one uppercase letter
            // - At least one lowercase letter
            // - At least one number
            // - At least one special character
            $password_regex = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]).{8,}$/';
            return preg_match($password_regex, $input) === 1;

        default:
            return false;
    }
}

// Redirect if already logged in
if(isset($_SESSION['admin_logged_in'])){
    header('location: index.php');
    exit;
}
    
if(isset($_POST['login-btn'])){    
    // Validate email
    if (!isset($_POST['email']) || !validate_input($_POST['email'], 'email')) {
        header('location: login.php?error=Invalid email format!');
        exit;
    }

    // Validate password
    if (!isset($_POST['password']) || !validate_input($_POST['password'], 'password')) {
        header('location: login.php?error=Invalid Credentials!');
        exit;
    }

    $email = $_POST['email'];
    $password = md5($_POST['password']);

    $stmt = $conn->prepare("SELECT admin_id, admin_name, admin_email, admin_password FROM admins WHERE admin_email = ? AND admin_password = ? LIMIT 1");

    $stmt->bind_param('ss',$email,$password);

    if($stmt->execute()){
        $stmt->bind_result($admin_id,$admin_name,$admin_email,$admin_password);
        $stmt->store_result();

        if($stmt->num_rows() == 1){
            $row = $stmt->fetch();

            $_SESSION['admin_id'] = $admin_id;
            $_SESSION['admin_name'] = $admin_name;
            $_SESSION['admin_email'] = $admin_email;
            $_SESSION['admin_logged_in'] = true;

            header('location: index.php?login_success=logged in successfully');
            exit;

        }else{
            header('location: login.php?error=Could not verify your account');
            exit;
        }

    }else{
        header('location: login.php?error=Something went wrong');
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
   

<style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #191C21;
            padding: 20px;
        }

        .login-container {
            background: #FDFEFF;
            padding: 40px 30px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            width: 100%;
            max-width: 400px;
            border: 1px solid #7AA9ED;
        }

        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }

        .login-header h1 {
            color: #333185;
            font-size: 28px;
            margin-bottom: 10px;
        }

        .login-header p {
            color: #191C21;
            font-size: 14px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #191C21;
            font-size: 14px;
            font-weight: 500;
        }

        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #7AA9ED;
            border-radius: 5px;
            font-size: 14px;
            transition: all 0.3s ease;
            background: #FDFEFF;
            color: #191C21;
        }

        .form-group input:focus {
            outline: none;
            border-color: #333185;
            box-shadow: 0 0 0 3px rgba(51, 49, 133, 0.1);
        }

        .form-group input::placeholder {
            color: #7AA9ED;
        }

        .login-btn {
            width: 100%;
            padding: 12px;
            background: #333185;
            border: none;
            border-radius: 5px;
            color: #FDFEFF;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .login-btn:hover {
            background: #7AA9ED;
            transform: translateY(-1px);
        }

        .error-message {
            background: #F4C2AA;
            color: #191C21;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
            display: none;
            border: 1px solid rgba(25, 28, 33, 0.2);
        }

        .error-message.show {
            display: block;
        }

        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>Admin Login</h1>
            <p>Please enter your credentials to continue</p>
        </div>
        
        <?php if(isset($_GET['error'])) { ?>
            <div class="error-message show">
                <?php echo htmlspecialchars($_GET['error']); ?>
            </div>
        <?php } ?>

        <form action="login.php" method="POST">
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="text" id="email" name="email" placeholder="Enter your email">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password">
            </div>
            
            <button type="submit" name="login-btn" class="login-btn">Login</button>
        </form>
    </div>
</body>
</html>
