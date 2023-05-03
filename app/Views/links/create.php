
<?= $this->extend('Views/links/layout') ?>


<?= $this->section('create-link') ?> 
<!-- <br>
<br>
<br> -->
<div class="m-sm-5 ">
    <div class="m-md-5">
        <div class="m-sm-5">


            <?php if(session()->getFlashdata('errorC') ?? false){?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="bi bi-exclamation-triangle-fill"></i> <?= session()->getFlashdata('errorC')?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            <?php }?>
            
            


            <h1>
                <?=$title; ?>
            </h1>

            <div class="alert alert-info alert-dismissible fade show" role="alert">
                <i class="bi bi-info-circle-fill"></i> 
                The  (<span class="text-danger dimisible">*</span>) indicate that the fields are required.
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>

                <!-- <i class="bi bi-exclamation-triangle-fill"></i>  -->
                
            <?=(session("isLoggedIn"))?"":"
            <div class='alert alert-warning alert-dismissible fade show' role='alert'>
                <i class='bi bi-exclamation-diamond-fill'></i> You need an account to use all services of this page. To log in this page, click <a href=".base_url('login').">login</a> or if you need to sign up, click  <a href=".base_url('register').">Sign up</a>.
            </div>
            "; ?>
                
                
                <!-- <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button> -->
            

            <form action="<?=base_url('link/create_post'); ?>" method="POST">
                <?=csrf_field(); ?>

                <div class="mt-3">
                    <label class="form-label  mb-2 mt-3  fw-bold" for="destination">Destination: <span class="text-danger">*</span> </label> <a href="#info-file" data-bs-toggle="collapse" role='button'><i class="bi bi-patch-question-fill text-primary" ></i></a>
                    <div class="alert alert-primary collapse" id="info-file" >
                        <h6><i class="bi bi-info-circle-fill"></i> info</h6>
                        <br>
                        If it reference a file, give the root and the name of file only to make the reference.
                    </div>
                    <input class="form-control <?=isset($_SESSION['destError']) ? "is-invalid":"" ; ?>"  type="text" placeholder="https://example.com/my-long-url" id="destination" name="destination" value="<?=old('destination'); ?>">

                        
                        <?php if( session()->getFlashdata('destError'))  { ?>
                            
                            <div class="invalid-feedback">
                                <!-- <i class="bi bi-exclamation-triangle-fill"></i>  -->
                                <?=session()->getFlashdata('destError'); ?>
                            </div>

                        <?php } ?>
                            
                </div>
                <div class="mt-3">

                    <label class="form-label  mb-2 mt-3  fw-bold" for="title">Title: </label>
                    <input class="form-control" <?=(session("isLoggedIn"))?"":"disabled"; ?> type="text" placeholder="Link for my commercial in Instagram..." id="title" name="title">
                            
                            
                </div>
                    
                <div class="mt-3">

                    <label class="form-label  mb-2 mt-3 fw-bold " for="description">Description: </label></br>
                    <!-- <input class="form-control" <?=(session("isLoggedIn"))?"":"disabled"; ?> type="text" placeholder="This link is for share my commercial with my clients. This commercial is about... " id="description" name="description"> -->
                    
                    <textarea name="description" <?=(session("isLoggedIn"))?"":"disabled"; ?> id="CKEditor-container" ></textarea>
                </div>


                <label for="basic-url" class="form-label mt-4 fw-bold">Your short URL  </label> <a href="#desc-link" data-bs-toggle="collapse" role='button'><i class="bi bi-patch-question-fill text-primary" ></i></a>
                <div class="alert alert-primary collapse" id="desc-link" >
                    <h6><i class="bi bi-info-circle-fill"></i> info</h6>
                    <br>
                    You can set your personalized URL in this form field. If you do not set a personalized URL, a random one will be generated for you.
                </div>
                <div class="input-group mb-3">
                
                    <span class="input-group-text" id="basic-addon3"><?=base_url('daw.li/'); ?></span>
                    <input type="text" <?=(session("isLoggedIn"))?"":"disabled"; ?> class="form-control" id="basic-url" name="short-url" aria-describedby="basic-addon3" placeholder="my-favourite-url">
                </div>

                
                <label for="expiration-date" class="form-label mt-4 fw-bold">Expiration date </label> <a href="#exp-date" data-bs-toggle="collapse" role='button'><i class="bi bi-patch-question-fill text-primary" ></i></a>
                <div class="alert alert-primary collapse" id ="exp-date"> 
                    <h6><i class="bi bi-info-circle-fill"></i> info</h6>
                    <br>
                    You can set an expiration date for a short link, so that when the date is reached, the link will stop working. If you do not set an expiration date, the link will never expire.  
                </div>
                <div class="input-group mb-3">
                    <input type="date" <?=(session("isLoggedIn"))?"":"disabled"; ?> class="form-control" id="expiration-date" name="expiration-date" style="max-width:200px">
                </div>


                <div class="input-group mb-3 mt-5">
                    <label for="create-file" class="list-group-item bs-0" >  
                        <input type="checkbox" <?=(session("isLoggedIn"))?"":"disabled"; ?> class="form-check-input me-2" id="create-file" name="associate-file" >
                        Associate on a file. 
                    </label>
                </div>

                <?php if(!session('isLoggedIn') ?? true){?>
                    <div class="form-group mt-3">
                        <label for="captcha" class="mt-5 mb-2 fw-bold"><?=lang('Auth.enterCaptcha')?></label>
                        <input type="text" name="captcha-link" class="form-control <?php if (session('errors.captcha')) : ?>is-invalid<?php endif ?>" placeholder="<?=lang('Auth.infoCaptcha')?>" autocomplete="off">
                    </div>
                    <?=$captcha; ?>
                <?php }?>


        
            
                <input class="btn btn-primary w-100 mt-5 p-2" type="submit" value="Create">
            </form>
        </div>
    </div>


    
</div>



<script>
    
    <?php if(session("isLoggedIn")??false){?>
        window.onload= function(){
            ClassicEditor
                .create( document.getElementById( 'CKEditor-container' ) )
                .catch( error => {
                    console.error( error );
                } );
            document.getElementsByClassName('ck-content')[0].children[0].setAttribute("name","description");
        }
    <?php }?>
</script>


<?= $this->endSection() ?>

