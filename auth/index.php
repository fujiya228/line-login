<?php
require '../vendor/autoload.php';
use Ramsey\Uuid\Uuid;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Dotenv\Dotenv;
use Dotenv\Loader;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$auth_endpoint = 'https://access.line.me/oauth2/v2.1/authorize';
$token_endpoint = 'https://api.line.me/oauth2/v2.1/token';
$client_id = getenv('CLIENT_ID');
$client_secret = getenv('CLIENT_SECRET');
$redirect_uri = getenv('REDIRECT_URI');
$host = getenv('HOST');
$dbname = getenv('DBNAME');
$dbusr = getenv('DBUSR');
$dbpass = getenv('DBPASS');
$method = $_SERVER["REQUEST_METHOD"];

session_save_path('../session/'); //index.phpのあるフォルダをルートとして
session_start();

if($method === 'POST'){// ログイン確認
    if (isset($_SESSION['loggedin'])){// ログイン済み
        $data['loggedin'] = true;
        if(isset($_SESSION['newAcount'])){// 新規登録後の場合
            $data['newAcount'] = true;
            unset($_SESSION['newAcount']);
        }
    } else {
        $data['loggedin'] = false;
    }
    $data['authPath'] = $redirect_uri.'/auth';
    $data['method'] = $method;
    header("Content-Type: application/json; charset=utf-8");
    header("Access-Control-Allow-Origin: *");
    echo json_encode($data);
    exit;
} elseif ($method === 'DELETE') {//ログアウト要求
    sessDestroy();
    $data = ['loggedin' => false];
    $data['authPath'] = $redirect_uri.'/auth';
    $data['method'] = $method;
    header("Content-Type: application/json; charset=utf-8");
    header("Access-Control-Allow-Origin: *");
    echo json_encode($data);
    exit;
}
if (!isset($_SESSION['loggedin']) && !isset($_SESSION['state'])) {// ログイン開始時
    $state = random(16);
    $nonce = Uuid::uuid4();
    $_SESSION['state'] = $state;
    $_SESSION['nonce'] = $nonce;
    $destination = $auth_endpoint . '?'
                    . 'response_type=code&'
                    . 'client_id=' . $client_id . '&'
                    . 'redirect_uri=' . $redirect_uri . '/auth&'
                    . 'scope=openid%20profile%20email&'
                    . 'state=' . $_SESSION['state'] . '&'
                    . 'nonce=' . $_SESSION['nonce'];
    header('Location: ' . $destination, true, 301);
    exit;
}
if (isset($_SESSION['loggedin'])) header('Location: ' . $redirect_uri, true, 301);//アクセスしてきた際にログイン済みな場合リダイレクト
if($_GET['state'] != $_SESSION['state']){// stateの検証
    echo 'state unmatch error';
    sessDestroy();
    exit;
}
unset($_SESSION['state']);
$data = array(
    'grant_type' => 'authorization_code',
    'code' => $_GET['code'],
    'redirect_uri' => $redirect_uri.'/auth',
    'client_id' => $client_id,
    'client_secret' => $client_secret
);
$options = array(
    'http' => array(
        'method'  => 'POST',
        'content' => http_build_query($data),
        'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
        )
);
$context  = stream_context_create( $options );
$result = file_get_contents($token_endpoint, false, $context );// tokenの取得
preg_match('/HTTP\/1\.[0|1|x] ([0-9]{3})/', $http_response_header[0], $matches);
$statusCode = (int)$matches[1];
$contents_array = array();
if($statusCode !== 200){// 取得の検証
    echo 'can not get response';
    sessDestroy();
    exit;
}
$result = json_decode($result);
if (!$result->{'id_token'}) {// id_tokenの存在検証
    echo 'id_token not provided error';
    sessDestroy();
    exit;
}
$signer = new Sha256();
$id_token = (new Parser())->parse((string) $result->{'id_token'});
if (!$id_token->verify($signer, $client_secret)) {// id_tokenの有効性検証
    echo 'verification error';
    sessDestroy();
    exit;
}
if ($id_token->getClaim('nonce') != $_SESSION['nonce']) {// nonceの検証
    echo 'nonce unmatch error';
    sessDestroy();
    exit;
}
unset($_SESSION['nonce']);
$uuid = $id_token->getClaim('sub');
try{
    $db = new PDO('mysql:dbname='.$dbname.';host='.$host.';charset=utf8', $dbusr, $dbpass);
    $sql = $db->prepare("SELECT * FROM user WHERE user_id = ?");
    $sql->bindValue(1, $uuid);
    $sql->execute();
    if($row = $sql->fetch()) {// 登録済みの場合
        $sql = $db->prepare("UPDATE user SET session_id = ?, updated_at = null WHERE user_id = ?");
        $sql->bindValue(1, session_id());
        $sql->bindValue(2, $uuid);
        $sql->execute();
        $_SESSION['loggedin'] = 1;
        header('Location: ' . $redirect_uri, true, 301);
    } else {                  // 新規登録の場合
        $sql = $db->prepare("INSERT INTO user(user_id,session_id) VALUE (?,?)");
        $sql->bindValue(1, $uuid);
        $sql->bindValue(2, session_id());
        $sql->execute();
        $_SESSION['loggedin'] = 1;
        $_SESSION['newAcount'] = 1;// 新規登録後のみ付与
        header('Location: ' . $redirect_uri, true, 301);
    }
} catch(PDOException $e) {
    sessDestroy();
    die('エラーメッセージ：'.$e->getMessage());
}


function random($length = 8){
    return substr(bin2hex(random_bytes($length)), 0, $length);
}

function sessDestroy(){
    $_SESSION = [];
    if (isset($_COOKIE[session_name()])) {
        $cparam = session_get_cookie_params();
        setcookie(session_name(), '', time() - 3600,
        $cparam['path'], $cparam['domain'],$cparam['secure'],$cparam['httponly']);
    }
    session_destroy();
}
?>
