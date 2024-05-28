<?php
session_start();
require 'connection1.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = strip_tags($_POST['password']);

    $stmt = $conn->prepare("SELECT * FROM account WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_object();

    if($user){
        $salt = $user->salt;
        $pass_hash= hash('sha3-512', $password.$salt);

        if($pass_hash == $user->password){
            // Settiamo l'ID dell'utente nella sessione
            $_SESSION['id_utente'] = $user->id;
            // Reindirizziamo l'utente alla home dell'area personale
            header("Location: ../../myarea/myareahome.php");
            exit();
        } else {
            // Password non corretta, reindirizziamo con un messaggio di errore
            header("Location: login.html?error=4"); 
            exit();
        }
    } else {
        // Utente non trovato, reindirizziamo con un messaggio di errore
        header("Location: login.html?error=4"); 
        exit();
    }
}
