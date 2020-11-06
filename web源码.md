##### 2020年全国电信和互联网行业网络安全管理职业技能竞赛

###### ezsqli

```
 <?php
//a "part" of the source code here

function sqlWaf($s)
{
    $filter = '/xml|extractvalue|regexp|copy|read|file|select|between|from|where|create|grand|dir|insert|link|substr|mid|server|drop|=|>|<|;|"|\^|\||\ |\'/i';
    if (preg_match($filter,$s))
        return False;
    return True;
}

if (isset($_POST['username']) && isset($_POST['password'])) {
    
    if (!isset($_SESSION['VerifyCode']))
            die("?");

    $username = strval($_POST['username']);
    $password = strval($_POST['password']);

    if ( !sqlWaf($password) )
        alertMes('damn hacker' ,"./index.php");

    $sql = "SELECT * FROM users WHERE username='${username}' AND password= '${password}'";
//    password format: /[A-Za-z0-9]/
    $result = $conn->query($sql);
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        if ( $row['username'] === 'admin' && $row['password'] )
        {
            if ($row['password'] == $password)
            {
                $message = $FLAG;
            } else {
                $message = "username or password wrong, are you admin?";
            }
        } else {
            $message = "wrong user";
        }
    } else {
        $message = "user not exist or wrong password";
    }
}

?> 
```

###### warmup

```
<?php
include 'flag.php';

 class SQL {
    public $table = '';
    public $username = '';
    public $password = '';
    public $conn;
    public function __construct() {
    }
    
    public function connect() {
        $this->conn = new mysqli("localhost", "xxxxx", "xxxx", "xxxx");
    }

    public function check_login(){
        $result = $this->query();
        if ($result === false) {
            die("database error, please check your input");
        }
        $row = $result->fetch_assoc();
        if($row === NULL){
            die("username or password incorrect!");
        }else if($row['username'] === 'admin'){
            $flag = file_get_contents('flag.php');
            echo "welcome, admin! this is your flag -> ".$flag;
        }else{
            echo "welcome! but you are not admin";
        }
        $result->free();
    }

    public function query() {
        $this->waf();
        return $this->conn->query ("select username,password from ".$this->table." where username='".$this->username."' and password='".$this->password."'");
    }

    public function waf(){
    	$blacklist = ["union", "join", "!", "\"", "#", "$", "%", "&", ".", "/", ":", ";", "^", "_", "`", "{", "|", "}", "<", ">", "?", "@", "[", "\\", "]" , "*", "+", "-"];
    	foreach ($blacklist as $value) {
    		if(strripos($this->table, $value)){
    			die('bad hacker,go out!');
    		}
    	}
        foreach ($blacklist as $value) {
            if(strripos($this->username, $value)){
                die('bad hacker,go out!');
            }
        }
        foreach ($blacklist as $value) {
            if(strripos($this->password, $value)){
                die('bad hacker,go out!');
            }
        }
    }

    public function __wakeup(){
        if (!isset ($this->conn)) {
            $this->connect ();
        }
        if($this->table){
            $this->waf();
        }
        $this->check_login();
        $this->conn->close();
    }

}
?>
```

###### SecretGuess

```
<html lang="zh">
<!--本题目不是爆破弱口令的题-->
<!--本题目也不是脑洞题，secret不是靠猜出来的-->
<!--hack me if you can-->
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secret Guess</title>
    <link rel="stylesheet" type="text/css" href="static/css/styles.css">
    <style>
        .botCenter{
            width:100%;
            height:35px;
            line-height:35px;
            background:#EEE5DE;
            position:fixed;
            bottom:0px;
            left:0px;
            font-size:14px;
            color:#000;
            text-align:center;
        }
    </style>
</head>


<body>
<div class="botCenter">
    <a href="/source" target="_blank">source</a>
</div>

<div class="htmleaf-container">
    <div class="wrapper">
        <div class="container">
            <h1 style="margin-top: 15%">Secret Guess!</h1>
            <h3 style="margin-top: 1%">DO NOT BRUTE FORCE SINCE THE SECRET IS SUPER STRONG</h3>
            <h5 style="margin-top: 1%">{{result}}</h5>
            <form class="form" action="" enctype="application/x-www-form-urlencoded" method="post" style="margin-top: 15%">
                <input type="text" name="auth"  style="width: 100%" placeholder="secret">
                <button type="submit" id="login-button" style="width: 40%;margin-top: 2%">Guess</button>
            </form>

        </div>

        <ul class="bg-bubbles">
            <li></li>
            <li></li>
            <li></li>
            <li></li>
            <li></li>
            <li></li>
            <li></li>
            <li></li>
            <li></li>
            <li></li>
        </ul>
    </div>
</div>

<script src="static/js/jquery-2.1.1.min.js" type="text/javascript"></script>

</body>
</html>
```

###### PNG Converter

```
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>gallery</title>
<style type="text/css">
	img{width:100px;height:100px;border:2px #cc0066 ridge;}
	ul{list-style-type:none;}
	li{float:left;}
  </style>
 </head>
 <body>
 <h2 align="center">@PNG_Converter</h2>
  <hr color="#00ff33" size="5">
  <marquee behavior="alternate">
  <ul>
	<li><img src="./images/img1.png" width="390" height="259" border="0" alt=""></li>
    <li><img src="./images/img2.png" width="400" height="300" border="0" alt=""></li>
	<li><img src="./images/img3.png" width="390" height="293" border="0" alt=""></li>
	<li><img src="./images/img4.png" width="400" height="253" border="0" alt=""></li>
	<li><img src="./images/img5.png" width="400" height="164" border="0" alt=""></li>
  </ul>
  </marquee>
   <hr color="#00ff33" size="5">
</body>
```

