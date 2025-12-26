# ChezToys
折腾 chez.com 免费空间的小工具，当然也可以用于其他免费空间。
目前(2025.12.16) chez.com 的免费空间 PHP 版本仍然是 5.2.6，非常老，很多程序都用不了，所以就找/改了些小工具自己用。

## 使用方法

下载对应的 PHP 文件，上传到你的空间，然后就能访问使用

## 说明
### 2008.php
这是一个来自安全天使的webshell，支持文件管理，MySQL管理，运行命令，运行PHP代码等。
因为 chez.com 的 FTP 只有法国家宽才能连，所以在线文件管理工具是必须的。
但是因为是在线管理，上传多个文件非常不方便，所以增加了tar.gz 解压的功能。
另外我增加了代码高亮的功能，这样编辑文件的时候舒服点。
我是从[这里](https://github.com/tennc/webshell/blob/master/php/phpspy/2008.php)下载的，安全性未知，请自行评估使用。

使用前请修改密码，免得被人猜到。
https://github.com/benzBrake/ChezToys/blob/7194894a9ecbbab427397fb4a62d84c0c008b8f7/2008.php#L48-L53

### phpminiadmin.php
这个找了我一个多小时，忘记从哪里找到的，可以在线管理 MySQL 数据库，支持导入导出，当然，我也简单改了一下来兼容 chez.com 的 PHP 环境。

使用前请修改密码，免得被人猜到。数据库连接信息可以不改。
https://github.com/benzBrake/ChezToys/blob/b6fc79e3bbed7dcb7da0b86d9b3eb931a2cb8459/phpminiadmin.php#L10-L21

PS：chez.com 的 MySQL 密码只会在创建数据库的时候显示一次，丢了就没办法找回。

### info.php
一个可以在 PHP 5.2.6 环境下运行的探针，可以用来查看 PHP 环境信息。

### phpZip.zip
这是里包含了 tar.gz 压缩工具和单个PHP文件的 tar.gz 解压脚本，解压脚本目前用不到了，但是你在Windows 下不会压缩 tar.gz 文件的话，可以用这个。