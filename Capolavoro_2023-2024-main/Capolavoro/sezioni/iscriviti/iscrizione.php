<?php
session_start();
    require 'connection.php';

    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
        $password = strip_tags($_POST['password']);
        $repeat_password = strip_tags ($_POST['repeat_password']);
        # Check if email or nickname already exists

        if ($password != $repeat_password) {
            header("Location: iscrizione.html?error=4"); 
            exit();
        }

        $stmt = $conn->prepare("SELECT * FROM coin WHERE email = ?");       #per i coin
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        $stmt = $conn->prepare("SELECT * FROM account WHERE email = ?");    #per la verifica
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            header("Location: register.php?error=email already exist");
            exit();
        }

        $coin=500;
        $salt = bin2hex(random_bytes(32));
     // Combine the password and the salt hash the result
        $hashed_password = hash('sha3-512', $password.$salt);


        $stmt = $conn->prepare("INSERT INTO coin (email, coin) VALUES (?, ?)");                         #per i coin
        $stmt->bind_param("si", $email, $coin);
        $stmt->execute(); 

        $stmt = $conn->prepare("INSERT INTO account (email, password, salt) VALUES (?, ?, ?)");         #per la verifica
        $stmt->bind_param("sss", $email, $hashed_password, $salt);
        $stmt->execute(); 

        $_SESSION['email'] = $email;
        header("Location: ../login/login.html");
    }
