
<?= $this->extend('Views/links/layout') ?>


<?= $this->section('list-users') ?> 


<h2><?=$title; ?></h2>
    <a class="btn btn-success mt-3" href="<?=base_url('admin/create')?>"><i class="bi bi-plus-circle"></i> New user</a>
    <table class="table table-stripped mt-4">
        <thead>
            <tr>
                <th>id</th>
                <th>Username</th>
                <th>Email</th>
                <th>Rols</th>
                <th>Status account</th>
                <th>Date created</th>
                <th>Last update</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            
        <?php foreach($users as $user){ ?>
            
            <tr>
                <td><?=$user->id; ?></td>
                <td><?=$user->username; ?></td>
                <td><?=$user->email; ?></td>
                <td><?=$user->Rols; ?></td>
                <td>
                    <?php if(session('user')->id != $user->id){?>
                        
                        <?php if($user->active ?? false){?>
                            <a class="btn btn-danger"  href="<?=base_url('admin/disabled-account/'.$user->id)?>">Disable</a>
                            
                            <?php }else{?>
                                <a class="btn btn-primary" href="<?=url_to('activate-account').'?token='.$user->activate_hash."&view=admin"?>">Activate</a>
                        
                        <?php }?>
                    
                    <?php }?>
                </td>
                <td><?=$user->created_at; ?></td>
                <td><?=$user->updated_at; ?></td>
                <td class="d-flex gap-2">
                    <a class="btn btn-primary"  href="<?= base_url('admin/edit/'.$user->id); ?>">Edit</a>
                    <?php if(session('user')->id != $user->id){?>
                        <form action="<?= base_url('admin/delete/'.$user->id); ?>" method="POST">
                            <?= csrf_field() ?>
                            <input onclick="return confirm('Are you shure you want to delete user: <?=$user->username; ?>')" class="btn btn-danger" type="submit" value="Delete">
                        </form>
                    
                    <?php }?>
                    <!-- <a class="btn btn-danger"  href="<?= base_url('admin/delete/'.$user->id); ?>">Delete</a> -->
                </td>
            </tr>
        <?php }?>

        </tbody>
    </table>

    <?=$pager->links('default', "bootstrap_pager_template"); ?>
<?= $this->endSection() ?>
