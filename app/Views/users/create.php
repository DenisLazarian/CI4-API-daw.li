
<?= $this->extend('Views/links/layout') ?>

<?= $this->section('user-create') ?> 

<div class="m-sm-5">
    <div class="m-sm-5">
        <div class="m-sm-5">
            <h2>
                <?=$title; ?>
            </h2> 
            <form class="mt-5" method="POST" action="<?=base_url('admin/save')?>">
                <?=csrf_field(); ?>
                <div class="mb-3">
                    <label for="email" class="form-label">Email address:</label>
                    <div id="emailHelp" class="form-text ">We'll never share your email with anyone else.</div>
                    <input type="email" name="email" class="form-control <?=session()->getFlashdata('errorMail') ?"is-invalid" :"" ?>" id="email" aria-describedby="emailHelp">
                    <?=session()->getFlashdata('errorMail')?  "<div class='invalid-feedback'>".session()->getFlashdata('errorMail')."</div>":"" ?>
                </div>
                <div class="mb-3">
                    <label for="username" class="form-label">Username:</label>
                    <input type="text" name="username" class="form-control" id="username">
                    
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label ">Password:</label>
                    <input type="password" name="password"  class="form-control <?=session()->getFlashdata('errorPass') ?"is-invalid" :"" ?>" id="password">
                    <?=session()->getFlashdata('errorPass')?  "<div class='invalid-feedback'>".session()->getFlashdata('errorPass')."</div>":"" ?>

                </div>
                <div class="mb-3">
                    <label for="passconf" class="form-label">Confirm password:</label>
                    <input type="password" name="passconf" class="form-control  <?=session()->getFlashdata('errorConf') ?"is-invalid" :"" ?>" id="passconf">
                    <?=session()->getFlashdata('errorConf')?  "<div class='invalid-feedback'>".session()->getFlashdata('errorConf')."</div>":"" ?>


                </div>
                <div class="mb-3">
                    <input type="checkbox" name="active" class="form-checkbox" id="active" value="1" name="active">
                    <label for="active"  class="form-label">Active</label>
                </div>
                <div class="mb-3">
                    <div for="active"  class="form-label fw-bold">Roles</div>
                    
                    <div class="d-flex gap-3 mt-3">
                        <?php foreach($groups as $group){?>
                            <input type="hidden" name="_role-<?=$group['id']; ?>" class="form-checkbox" id="_role-<?=$group['id']; ?>" value="" checked="false" >
                            <div class="">
                                <input type="checkbox" name="role-<?=$group['id']; ?>" class="form-checkbox" id="role-<?=$group['id']; ?>" value="<?=$group['name']; ?>" checked="false"  >
                                <label for="role-<?=$group['id']; ?>"  class="form-label" ><?=$group['name']; ?></label>
                            </div>
                        <?php }?>
                        
                    </div>
                </div>

                

                
                <button type="submit" class="btn btn-primary w-100 mt-4">Submit</button>
            </form>

        </div>
    </div>

</div>

<?= $this->endSection() ?>
