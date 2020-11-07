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

##### 中国科学技术大学第七届信息安全大赛

###### 超简易的网盘服务器

```
worker_processes 1;
error_log stderr warn;
pid /run/nginx.pid;
user nobody;

events {
    worker_connections 1024;
}

http {
    include mime.types;
    default_type application/octet-stream;

    # Define custom log format to include reponse times
    log_format main_timed '$remote_addr - $remote_user [$time_local] "$request" '
                          '$status $body_bytes_sent "$http_referer" '
                          '"$http_user_agent" "$http_x_forwarded_for" '
                          '$request_time $upstream_response_time $pipe $upstream_cache_status';

    access_log /dev/stdout main_timed;
    error_log /dev/stderr notice;

    keepalive_timeout 65;

    server_tokens off;

    # Write temporary files to /tmp so they can be created as a non-privileged user
    client_body_temp_path /tmp/client_temp;
    proxy_temp_path /tmp/proxy_temp_path;
    fastcgi_temp_path /tmp/fastcgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    scgi_temp_path /tmp/scgi_temp;

server{
    # Docker 内部的地址，无关紧要
    listen 10120;
    server_name _;

    root /var/www/html;
    index index.php index.html /_h5ai/public/index.php;

    # _h5ai/private 文件夹下的内容是不可直接访问的，设置屏蔽
    location ~ _h5ai/private {
        deny all;
    }

    # 根目录是私有目录，使用 basic auth 进行认证，只有我（超极致的小 C)自己可以访问
    location / {
        auth_basic "easy h5ai. For visitors, please refer to public directory at `/Public!`";
        auth_basic_user_file /etc/nginx/conf.d/htpasswd;
    }

    # Public 目录是公开的，任何人都可以访问，便于我给大家分享文件
    location /Public {
        allow all;
        index /Public/_h5ai/public/index.php;
    }

    # PHP 的 fastcgi 配置，将请求转发给 php-fpm
    location ~ \.php$ {
             fastcgi_pass   127.0.0.1:9000;
             fastcgi_index  index.php;
             fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
             include        fastcgi_params;
    }

    location ~ /\. {
        log_not_found off;
        deny all;
    }
}
    
    gzip on;
    gzip_proxied any;
    gzip_types text/plain application/xml text/css text/js text/xml application/x-javascript text/javascript application/json application/xml+rss;
    gzip_vary on;
    gzip_disable "msie6";
    
    # Include other server configs
    include /etc/nginx/conf.d/*.conf;
}
```

###### 超迷你的挖矿模拟器

```
package cn.edu.ustc.lug.hack.miniminer;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Game instance per user
 */
public final class Game {

    public static Game refresh(User user, Game old) {
        return old != null && Instant.now().isBefore(old.expiration) ? old : new Game(user);
    }

    public JSONObject damage(Map<String, List<String>> params) {
        var material = Material.valueOf(params.get("material").get(0));
        var x = Integer.parseInt(params.get("x").get(0));
        var y = Integer.parseInt(params.get("y").get(0));
        var location = new Location(x, y);
        var result = new JSONObject();
        if (location.getMaterial().harderThan(material)) {
            this.waitFor(LONG_DURATION);
            result.put("dropped", Material.AIR.name()).put("flag", "");
        } else {
            this.waitFor(SHORT_DURATION);
            result.put("dropped", location.getMaterial().name());
            result.put("flag", location.getMaterial().flagOf(this.currentUser));
        }
        this.airLocations.add(location);
        return result;
    }

    public JSONObject reset(Map<String, List<String>> params) {
        this.baseSeed = (this.baseSeed << 3) | (BASE_SEED_RNG.nextInt() & 7);
        this.expiration = Instant.now().plus(EXPIRATION);

        this.airLocations.clear();
        this.airLocations.add(new Location(15, 15));
        this.airLocations.add(new Location(15, 16));
        this.airLocations.add(new Location(16, 15));
        this.airLocations.add(new Location(16, 16));

        return new JSONObject().put("user", this.currentUser).put("expiration", this.expiration);
    }

    public JSONObject state(Map<String, List<String>> params) {
        var x = Integer.parseInt(params.get("x").get(0));
        var y = Integer.parseInt(params.get("y").get(0));
        var minX = Math.floorDiv(x, 32) * 32;
        var minY = Math.floorDiv(y, 32) * 32;
        var materials = new JSONArray();
        for (var i = 0; i < 32; ++i) {
            var materialsPerLine = new JSONArray();
            for (var j = 0; j < 32; ++j) {
                materialsPerLine.put(new Location(minX + i, minY + j).getMaterial());
            }
            materials.put(materialsPerLine);
        }
        var min = new JSONArray().put(minX).put(minY);
        return new JSONObject().put("materials", materials).put("min", min);
    }

    private static final Duration SHORT_DURATION = Duration.ofSeconds(3);
    private static final Duration LONG_DURATION = Duration.ofSeconds(5);
    private static final Duration EXPIRATION = Duration.ofMinutes(30);

    private static final Random BASE_SEED_RNG = new SecureRandom();

    private final Set<Location> airLocations;
    private final User currentUser;
    private Instant expiration;
    private long baseSeed;

    private Game(User currentUser) {
        this.expiration = Instant.now().plus(EXPIRATION);
        this.baseSeed = BASE_SEED_RNG.nextLong();

        this.airLocations = ConcurrentHashMap.newKeySet();
        this.airLocations.add(new Location(15, 15));
        this.airLocations.add(new Location(15, 16));
        this.airLocations.add(new Location(16, 15));
        this.airLocations.add(new Location(16, 16));
        this.currentUser = currentUser;
    }

    private void waitFor(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private final class Location {
        private final int x;
        private final int y;

        private Location(int x, int y) {
            this.x = x;
            this.y = y;
        }

        private Material getMaterial() {
            var rng = new Random();
            var result = Material.AIR;
            if (!Game.this.airLocations.contains(this)) {
                for (var i = 1; i <= 5; ++i) {
                    var material = Material.values()[i];
                    var modular = material.size + material.size / 2;
                    var chunkX = Math.floorDiv(this.x, material.size);
                    var chunkY = Math.floorDiv(this.y, material.size);
                    var offsetX = Math.floorMod(this.x, material.size);
                    var offsetY = Math.floorMod(this.y, material.size);
                    rng.setSeed(Game.this.baseSeed ^ (i + 0x6E5D5AF15FA1280BL * chunkX + 0xE9716B1CE6339E6CL * chunkY));
                    for (var j = 0; j < material.count; ++j) {
                        var randomX = Math.floorMod(rng.nextInt() * ((1 << j) - 1) + chunkX + 1, modular);
                        var randomY = Math.floorMod(rng.nextInt() * ((1 << j) - 1) + chunkY + 1, modular);
                        if (randomX == offsetX && randomY == offsetY) {
                            result = material;
                        }
                    }
                }
            }
            return result;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Location && this.x == ((Location) o).x && this.y == ((Location) o).y;
        }

        @Override
        public int hashCode() {
            return 31 * this.x + this.y;
        }
    }

    private enum Material {
        AIR(1, 1), STONE(1, 1), IRON(32, 16), DIAMOND(32, 32), OBSIDIAN(16, 32), FLAG(2, 16777216);

        // ordinal: air 0, stone 1, iron 2, diamond 3, obsidian 4, flag 5

        private final int count;
        private final int size;

        Material(int count, int size) {
            this.count = count;
            this.size = size;
        }

        private boolean harderThan(Material other) {
            return this == FLAG || this.ordinal() > other.ordinal() + 1;
        }

        private String flagOf(User user) {
            return this == FLAG ? user.getFlag() : "";
        }
    }
}
```

