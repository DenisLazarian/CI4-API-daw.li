

 

<!-- <?=session('user')->active ?? "No Session" ?>
<?=base_url(); ?>  fixed-top-->
<header class="p-3 mb-3 border-bottom bg-white shadow ">
  <nav class="container">
    <div class="d-flex flex-wrap align-items-center justify-content-center justify-content-lg-start ">
      <a href="/" class="d-flex align-items-center mb-2 mb-lg-0 text-dark text-decoration-none">
        <img src="<?=base_url('daw.li_LOGO.JPG'); ?>" alt="Icono de la pagina daw.li" width="40" height="40" class="me-2">
      </a>

      <ul class="nav col-12 col-lg-auto me-lg-auto mb-2 justify-content-center mb-md-0">
        <li><a href="/" class="nav-link px-2 link-secondary">Home</a></li>
        <li><a href="#" class="nav-link px-2 link-dark">About</a></li>
        <!-- <li><a href="/contact" class="nav-link px-2 link-dark">Contact</a></li> -->

        <li class="nav-item dropdown">
          
          <a class="nav-link dropdown-toggle text-dark" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
            Administration
          </a>
          <ul class="dropdown-menu" aria-labelledby="navbarDropdown">
            <li><a class="dropdown-item" href="<?=base_url('link')?>">Links management</a></li>
            <li><hr class="dropdown-divider"></li>
            <li><a class="dropdown-item" href="<?=base_url('admin')?>">Users management</a></li>
            <li><hr class="dropdown-divider"></li>
            <li><a class="dropdown-item" href="<?=base_url('filemanager')?>">Files management</a></li>
          </ul>
        </li>
      </ul>
      

      <div class="text-end d-flex">
        
        <!-- <form action="" class="col-12 col-lg-auto mb-3 mb-lg-0 me-sm-3 d-flex gap-2">
          <input type="search" class="form-control" placeholder="Search..." aria-label="Search">
          <input type="submit" class="btn btn-outline-primary" value="Search">
        </form> -->
        <!-- <a href="#" class="text-prmary me-4 position-relative">
            <img class="mt-1" width="25" height="25"  src="<?=base_url('bell-solid.svg')?>" alt="bell icon for notify">
            <span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">5</span>
        </a> -->
        <div class="dropdown text-end">
          <a href="#" class="d-block link-dark text-decoration-none dropdown-toggle" id="dropdownUser" data-bs-toggle="dropdown" aria-expanded="false">

            <!-- <img src="https://github.com/mdo.png" alt="mdo" width="32" height="32" class="rounded-circle"> -->
            <?php if(session('isLoggedIn')){ ?>
                <?=session('captcha'); ?>
              <?php }else{ ?>
                <img class="rounded-circle border border-1 border-dark" height="36" width="36" src="<?=base_url("user-solid.svg"); ?>" alt="icono de usuario sin loggear">
              <?php } ?>

          </a>
          <ul class="dropdown-menu text-small" aria-labelledby="dropdownUser">
            
          <li  class="m-3 text-center">
            <div>
                <?php if(session('isLoggedIn')){ ?>
                  <?=session('captcha2'); ?>
                <?php }else{ ?>
                  <img class="rounded-circle border border-1 border-dark" height="50" width="50" src="<?=base_url("user-solid.svg"); ?>" alt="icono de usuario sin loggear">
                <?php } ?>
            </div>
            <div class="w-100 mt-2">
              <div class="d-inline-block mt-1"> 
                <?php echo (session('user')->username ?? "not registered") ?>
              </div>
              <div class="d-inline-block mt-1 text-secondary"> <?php echo (session('user')->email ?? "not registered") ?></div>
            </div>
          </li>
          <li>
            <hr class="dropdown-divider">
          </li>
          <li>
            <a class="dropdown-item" href="#"> <i class="bi bi-person-square"></i> Profile </a>
          </li>
          <li>
            <hr class="dropdown-divider">
          </li>
          
          <li class="d-flex">
          <?php if(session('isLoggedIn')){ ?>

            <a class="dropdown-item" href="<?=base_url('logout'); ?>"> <i class="bi bi-box-arrow-right"></i> Sign out</a>
            
          <?php }else{ ?>
            <a class="dropdown-item" href="<?=base_url('login'); ?>"> <i class="bi bi-box-arrow-in-right"></i> Sign in</a>    
            <?php } ?>
              
          </li>

          </ul>
        </div>

      </div>
    </div>
  </nav>


</header>


