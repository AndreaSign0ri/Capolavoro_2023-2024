<!DOCTYPE html>
<html>
<head>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="../css/style.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
</head>


<body style="background-color: whitesmoke;">
 
  <div class="topnav" id="myTopnav">
    <center>
        <a href="../index.html" class="active">Home</a>
        <a href="../sezioni/chisono.html">Chi sono</a>
        <a href="../sezioni/login/login.html">Login</a>
        <a  href="javascript:void(0);" class="icon" onclick="myFunction()">
        <i class="fa fa-bars"></i>
        </a>
        <a href="https://www.itispaleocapa.edu.it/" target="_blank" rel="noopener noreferrer">Paleocapa</a>
    </center>
    <a class="elimina_account"  style="float: inline-end;"  >elimina account</a>
  </div>

  
    <div class="flex items-center gap-4" style="padding-top: 3%;">
        <img class="w-10 h-10 rounded-full" src="../foto/foto_default.jpg" alt="">
        <div class="font-medium dark:text-white">
            <div>Account di:</div>
            <div class="text-sm text-gray-500 dark:text-gray-400">
            <?php
            session_start();
            require 'connection2.php';

            if (isset($_SESSION['id_utente'])) {
                // Ottieni l'ID dell'utente dalla sessione
                $user_id_from_session = $_SESSION['id_utente'];

                // Prepara la query per ottenere l'email dell'utente loggato
                $query = "SELECT email FROM account WHERE id = $user_id_from_session";

                // Esegui la query
                $result = mysqli_query($conn, $query);

                // Controlla se le query sono state eseguite con successo
                if ($result) {
                    // Controlla se è stata trovata almeno una riga per entrambe le query
                    if (mysqli_num_rows($result) > 0 ) {
                        // Ottieni i dati delle righe
                        $row = mysqli_fetch_assoc($result);
                        // Stampa l'email dell'utente e i suoi coin
                        echo $row['email'] ." hai: ";
                    } else {
                        echo "Nessun utente o  trovato con questo ID.";
                    }
                } else {
                    echo "Errore nella query: ".mysqli_error($conn);
                }
            } else {
                echo "Utente non loggato.";
            }


            if (isset($_SESSION['id_utente'])) {
                // Ottieni l'ID dell'utente dalla sessione
                $user_id_from_session = $_SESSION['id_utente'];

                // Prepara la query per ottenere l'email dell'utente loggato
                $query1 = "SELECT coin FROM coin WHERE id = $user_id_from_session";

                // Esegui la query
                $result1 = mysqli_query($conn, $query1);

                // Controlla se le query sono state eseguite con successo
                if ($result1) {
                    // Controlla se è stata trovata almeno una riga per entrambe le query
                    if (mysqli_num_rows($result1) > 0 ) {
                        // Ottieni i dati delle righe
                        $row = mysqli_fetch_assoc($result1);
                        // Stampa l'email dell'utente e i suoi coin
                        echo $row['coin']."A$";
                    } 
                } 
            }
            mysqli_close($conn);
            ?>

            </div>
        </div>
    </div>
    

  <div style="padding-top: 1%;" class="relative overflow-x-auto shadow-md sm:rounded-lg">
    <table class="w-full text-sm text-left rtl:text-right text-gray-500 dark:text-gray-400">
        <thead class="text-xs text-gray-700 uppercase bg-gray-50 dark:bg-gray-700 dark:text-gray-400">
            <tr>
                <th scope="col" class="px-6 py-3">
                    Product name
                </th>
                <th scope="col" class="px-6 py-3">
                    Difficulty (1-5)
                </th>
                <th scope="col" class="px-6 py-3">
                    Space
                </th>
                <th scope="col" class="px-6 py-3">
                    Price
                </th>
                <th scope="col" class="px-6 py-3">
                    Action
                </th>
            </tr>
        </thead>
        <tbody>
            <tr class="bg-white border-b dark:bg-gray-800 dark:border-gray-700">
                <th scope="row" class="px-6 py-4 font-medium text-gray-900 whitespace-nowrap dark:text-white">
                    Third library
                </th>
                <td class="px-6 py-4">
                    2
                </td>
                <td class="px-6 py-4">
                    3K
                </td>
                <td class="px-6 py-4">
                    A$ 2999
                </td>
                <td class="px-6 py-4">
                    <a href="#" rel="nofollow" class="font-medium text-blue-600 dark:text-blue-500 hover:underline" onclick="downloadFile()">Buy</a>
                </td>
            </tr>
            <tr class="bg-white border-b dark:bg-gray-800 dark:border-gray-700">
                <th scope="row" class="px-6 py-4 font-medium text-gray-900 whitespace-nowrap dark:text-white">
                    Robotic vacuum cleaner
                </th>
                <td class="px-6 py-4">
                    3
                </td>
                <td class="px-6 py-4">
                    2K
                </td>
                <td class="px-6 py-4">
                    A$ 1999
                </td>
                <td class="px-6 py-4">
                    <a href="#"class="font-medium text-blue-600 dark:text-blue-500 hover:underline">Buy</a>
                </td>
            </tr>
            <tr class="bg-white dark:bg-gray-800">
                <th scope="row" class="px-6 py-4 font-medium text-gray-900 whitespace-nowrap dark:text-white">
                    The scientist
                </th>
                <td class="px-6 py-4">
                    4
                </td>
                <td class="px-6 py-4">
                    5K
                </td>
                <td class="px-6 py-4">
                    A$ 99
                </td>
                <td class="px-6 py-4">
                    <a href="#" class="font-medium text-blue-600 dark:text-blue-500 hover:underline">Buy</a>
                </td>
            </tr>
        </tbody>
    </table>

    <div class="noire_line">
    <img src="../foto/divisore.png" alt="logo" class="logo_sep">

  </div>

  <div class="info">
    <center class="info_text">
      <p>Per segnalare eventuali bug scrivere una mail a</p>
      <p>signoriandrea7@gmail.com</p>
    </center>
  </div>
  
</div>

