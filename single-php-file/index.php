<?php
session_start();
/**
 * Simple webhard in a single file.
 * 
 * https://github.com/webstory/webhard
 *
 * WARNING! This program provides lacks of security.
 * Use this for small, personal purpose only.
 *
 * Most important thing: Discard after use.
 * 
 * @version 0.1.0
 * @author Hoya Kim(wbstory@storymate.net)
 * @license MIT
 */

/* Security Configuration */
$salt = $_SERVER['SERVER_NAME'];   // Any string
$hash_iteration_count = 54321;     // Higher is better
/**************************/

function path_join($path_arr) {
  $joined_path = implode("/", $path_arr);
  $normalized_path =  preg_replace("/\/+/","/",$joined_path);
  $canonicalized_path = preg_replace("/\/.+?\/\.\./","/", $normalized_path);

  return $canonicalized_path;
}

function is_authorized() {
  return isset($_SESSION['token']) && $_SESSION['token'] == session_id();
}

$method = $_SERVER['REQUEST_METHOD'];
$current_uri = $_SERVER['REQUEST_URI'];

$basepath = dirname(__FILE__);
$path = isset($_GET['dir'])? urldecode($_GET['dir']) : "/";

$curpath = path_join([$basepath, $path]);

// Security check step 1
// Check path is directory
if(!is_dir($curpath)) {
  header('HTTP/1.1 404 Not Found');
  die("<script>alert('".$path." is not a directory.'); window.history.back();</script>");
}

// Security check step 2
// Update password
// Set default password if not present
if(!file_exists("password.txt") && !file_exists("password.hash")) {
  file_put_contents("password.txt", "opensesame");
}

if(file_exists("password.txt")) {
  $password = trim(file_get_contents("password.txt"));
  $digest = hash_pbkdf2("sha512", $password, $salt, $hash_iteration_count, 64);
  file_put_contents("password.hash", $digest);
  unlink("password.txt");
}

// Security check step 3
// Chroot jail
if(strpos(realpath($curpath),realpath($basepath)) === false) {
  header('HTTP/1.1 403 Forbidden');
  die("<script>alert('Access violation!'); window.history.back();</script>");
}

// Security check step 4
// Is authorized
// Special behavior: Display login dialog
if(!is_authorized()) {
  // Check if login action
  if(isset($_GET['action']) && $_GET['action'] == 'login') {
    $hash1 = file_get_contents("password.hash");
    $hash2 = hash_pbkdf2("sha512", $_POST['password'], $salt, $hash_iteration_count, 64);

    if($hash1 == $hash2) {
      $_SESSION['token'] = session_id();
    }

    ?>
    <script>location.href = "<?=$_SERVER['PHP_SELF']?>?dir=/"</script>
    <?php
  } else { // Not login action
    $method = "AUTH";
    render();
  }
} else { // Authorized
  $action = isset($_GET['action']) ? $_GET['action'] : "";

  switch($action) {
    case 'logout':
      session_destroy();
      ?>
      <script>location.href = "<?=$_SERVER['PHP_SELF']?>?dir=/"</script>
      <?php
    break;

    case 'mkdir':
      mkdir(path_join([$curpath,$_GET['name']]));
      ?>
      <script>location.href = "<?=$_SERVER['PHP_SELF']?>?dir=<?=$path?>"</script>
      <?php
    break;

    case 'rmdir':
      rmdir(path_join([$curpath,$_GET['name']]));
      ?>
      <script>location.href = "<?=$_SERVER['PHP_SELF']?>?dir=<?=$path?>"</script>
      <?php
    break;

    case 'rm';
      unlink(path_join([$curpath,$_GET['name']]));
      ?>
      <script>location.href = "<?=$_SERVER['PHP_SELF']?>?dir=<?=$path?>"</script>
      <?php
    break;

    default:
      render();
    break;
  }
}

// Routers
function login_form() {
  ?>
  <div class="container">
    <div class="panel panel-default center-block" style="width:50%">
      <div class="panel-heading">
        <h4 class="panel-title">Webhard</h4>
      </div>
      <div class="panel-body">
        <form method="POST" action="<?=$_SERVER['PHP_SELF']?>?dir=/&action=login">
        <div class="input-group">
          <span class="input-group-addon">Password</span>
          <input name="password" class="form-control" type="password" id="pw" placeholder="opensesame"/>
        </div>
        <button type="submit" class="btn btn-primary btn-block">Login</button>
        </form>
      </div>
    </div>
  </div>
  <?php
}


function list_directory() {
  global $path, $curpath;

  function entries($path) {
    function cmp($a, $b) {
      return strcmp($a["name"], $b["name"]);
    }

    if ($path[strlen($path)-1] != '/') $path .= '/';
    if (!is_dir($path)) return array();

    $dir_handle  = opendir($path);
    $dir_objects = array();
    while ($entry = readdir($dir_handle)) {
      $fullpath    = path_join([$path, $entry]);
      $file_object = array(
        'name' => $entry,
        'size' => filesize($fullpath),
        'type' => filetype($fullpath),
        'time' => date("d M Y H:i", filemtime($fullpath))
      );
      array_push($dir_objects, $file_object);
    }
    usort($dir_objects, "cmp");
     return $dir_objects;
  }

  ?>
  <div class="panel panel-default">
    <h2>Current Directory : <span><?=$path?></span></h2>
  </div>
  <?php
    if(is_writable($curpath)) {
      ?>
      <div class="container-fluid">
        <div class="pull-left">
          <form class="form-inline" action="<?=$_SERVER['PHP_SELF']?>?dir=<?=$path?>" method="post" enctype="multipart/form-data">
            <span class="form-control btn btn-default btn-file"><input type="file" name="file" id="file"/></span>
            <input class="btn btn-info" type="submit" name="submit" value="Upload" />
          </form>
        </div>
        <div class="pull-right">
          <button class="btn btn-success" onclick='mkdir();'>New Directory</button>
          <button class="btn btn-danger" onclick='location.href="<?=$_SERVER['PHP_SELF']?>?dir=/&action=logout"'>Logout</button>
        </div>
      </div>
      <?php
    } else {
      ?>
      <p class="text-danger bg-danger">Write-protected</p>
      <?php
    }
  ?>
  <table class="table table-collapse table-striped">
    <thead>
      <tr><th>Name</th><th>Size</th><th>Type</th><th>Date</th></tr>
    </thead>
    <tbody>
      <?php
      foreach(entries($curpath) as $entry) {
        $link_title = $entry['name'];

        if($entry['type']=='dir') {
          $href = $_SERVER['PHP_SELF']."?dir=".path_join([$path,$entry['name']]);
          ?>
          <tr class="directory">
            <td>
              <a href="<?=$href?>"><?=$link_title?></a>
              <?php
                if($entry['name'] !== '.' && $entry['name'] !== '..') {
                ?>
                <button class="btn btn-sm btn-danger pull-right" onclick="rmdir('<?=$entry['name']?>')">
                  <i class="fa fa-trash"></i>
                </button>
                <?php
              }
              ?>
            </td>
            <td>-</td>
            <td>Dir</td>
            <td><?=$entry['time']?></td>
          </tr>
          <?php
        } else if($entry['type']=='file') {
          $href = path_join([dirname($_SERVER['PHP_SELF']),$path,$entry['name']]);
          ?>
          <tr class="file">
            <td>
              <a href="<?=$href?>" target="_blank"><?=$link_title?></a>
              <button class="btn btn-sm btn-danger pull-right" onclick="rm('<?=$entry['name']?>')">
                <i class="fa fa-trash"></i>
              </button>
            </td>
            <td><?=$entry['size']." bytes"?></td>
            <td>File</td>
            <td><?=$entry['time']?></td>
          </tr>
          <?php
        }
      }
      ?>
    </tbody>
  </table>
  <?php
}

function upload_file() {
  global $curpath;

  // Should not accept php extension
  if ($_FILES["file"]["error"] == 0) {
    $fullpath=path_join([$curpath,$_FILES["file"]["name"]]);
    move_uploaded_file($_FILES["file"]["tmp_name"],$fullpath);
    ?>
      <script>reload();</script>
    <?php
  } else {
  ?>
    <script>alert("Upload Failed."); reload();</script>
  <?php
  }
}

function route() {
  global $method;

  switch ($method) {
    case 'GET':
      list_directory();
      break;
    case 'POST':
      upload_file();
      break;
    case 'AUTH':
      login_form();
      break;
    default:
      break;
  }
}

function render() {
  global $path;
  ?>
  <!doctype html>
  <html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, user-scalable=no" />
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/bootstrap/3.3.6/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/flat-ui/2.2.2/css/flat-ui.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/fontawesome/4.5.0/css/font-awesome.min.css">
    <script src="https://cdn.jsdelivr.net/jquery/2.2.2/jquery.min.js"></script>
    <script src="https://cdn.jsdelivr.net/bootstrap/3.3.6/js/bootstrap.min.js"></script>

    <style>
      .directory {
        font-weight:bold;
      }

      .file {
      }
    </style>
    <script>
      function reload() {
        var loc = window.location;
        window.location = loc.protocol + '//' + loc.host + loc.pathname + loc.search;
      }

      function rm(name) {
        var result = confirm(name+" will be removed. Are you Sure?");

        if(result) {
          location.href = "<?=$_SERVER['PHP_SELF']?>?dir=<?=$path?>&action=rm&name="+name;
        }
      }

      function rmdir(name) {
        var result = confirm(name+" will be removed. Are you Sure?");
        
        if(result) {
          location.href = "<?=$_SERVER['PHP_SELF']?>?dir=<?=$path?>&action=rmdir&name="+name;
        }
      }

      function mkdir() {
        var newdir = prompt("Directory name", "");

        if(!!newdir && /^[^ ]+/.test(newdir)) {
          location.href = "<?=$_SERVER['PHP_SELF']?>?dir=<?=$path?>&action=mkdir&name="+newdir;
        }

        return false;
      }
    </script>

  </head>
  <body>
    <?php
      route();
    ?>

  </body>
  </html>
  <?php
}
?>