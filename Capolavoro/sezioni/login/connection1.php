<?php
    $servername = "localhost";
    $username = "root";
    $password = "";
    $database = "sito_personale";

    $conn = new mysqli($servername, $username, $password, $database);

    if ($conn->connect_error) {
        echo("Connessione fallita: " . $conn->connect_error . ".");
        exit();
    }

