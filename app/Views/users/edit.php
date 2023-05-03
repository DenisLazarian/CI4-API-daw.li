
<?= $this->extend('Views/links/layout') ?>

<?= $this->section('user-edit') ?> 

<div class="m-sm-5">
    <div class="m-sm-5">
        <div class="m-sm-5">
            <h2>
                <?=$title; ?>
            </h2> 
            <form class="mt-5" method="POST" action="<?=base_url('admin/update/'.$user['id'])?>">
                <?=csrf_field(); ?>
                <div class="mb-3">
                    <label for="email" class="form-label">Email address:</label>
                    <div id="emailHelp" class="form-text ">We'll never share your email with anyone else.</div>
                    <input value="<?=$user['email']; ?>" type="email" name="email" class="form-control <?=session()->getFlashdata('errorMail') ?"is-invalid" :"" ?>" id="email" aria-describedby="emailHelp">
                    <?=session()->getFlashdata('errorMail')?  "<div class='invalid-feedback'>".session()->getFlashdata('errorMail')."</div>":"" ?>
                </div>
                <div class="mb-3">
                    <label for="username" class="form-label">Username:</label>
                    <input value="<?=$user['username']; ?>" type="text" name="username" class="form-control" id="username">
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
                    <input type="checkbox" <?=$user['active'] == 1 ?'checked="checked"': ''; ?> name="active" class="form-checkbox" id="active" value="1" name="active">
                    <label for="active"   class="form-label">Active</label>
                </div>
                <div class="mb-3">
                    <div for="active"  class="form-label fw-bold">Roles <a  data-bs-toggle="collapse" href="#info-role" role="button" aria-expanded="false" aria-controls="info-role"><i class="bi bi-patch-question-fill"></i></a> </div> 

                    <div id="info-role" class="alert alert-primary collapse" role="alert">
                        <h4 class="alert-heading"><i class="bi bi-info-circle-fill"></i> info</h4>
                        <p>You can set or remove role in this section, if  the checkbox is checked, it means  the user already has the role.</p>
                        <ul>
                            <li>To set a rol, check the checkbox.</li>
                            <li>To remove a rol, unchek the checkbox.</li>
                        </ul>
                        
                    </div>
                    
                    <div class="d-flex gap-3 mt-3">
                        <?php 
                        $i=0;
                        foreach($groups as $group){?>
                            <input type="hidden" name="_role-<?=$group['id']; ?>" class="form-checkbox" id="_role-<?=$group['id']; ?>" value='<?=$groupsVal[$i]['checked']?"true" :"false" ?>' checked="false" >
                            <div class="">
                                <input type="checkbox" name="role-<?=$group['id']; ?>" class="form-checkbox" id="role-<?=$group['id']; ?>" value="<?=$group['name']; ?>" <?=$groupsVal[$i]['checked']?"checked='checked'" :"" ?> >
                                <label for="role-<?=$group['id']; ?>"  class="form-label" ><?=$group['name']; ?></label>
                            </div>
                        <?php 
                        $i++;
                        }?>
                        
                    </div>
                </div>

                

                
                <button type="submit" class="btn btn-primary w-100 mt-4">Submit</button>
            </form>

        </div>
    </div>

</div>

<?= $this->endSection() ?>
