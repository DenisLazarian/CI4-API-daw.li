<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= csrf_hash() ?>">
    <title>Document</title>
    <style>
        a.disabled {
            pointer-events: none;
            cursor: default;
        }
    </style>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.4/font/bootstrap-icons.css">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>

<!-- <script src="<?=base_url('public/build/ckeditor.js')?>"></script> -->
<script src="https://cdn.ckeditor.com/ckeditor5/37.0.1/classic/ckeditor.js"></script>

</head>
<body class="bg bg-white">

<?=view("Views/links/_navbar"); ?>



<div class="container ">
    <?php if(session()->getFlashdata('error')?? false){?>
        <div class="alert alert-warning">
            <i class="bi bi-exclamation-triangle-fill"></i> <?=session()->getFlashdata('error'); ?>
        </div>
    
    <?php }?>

<?php if($controller == 'privateSpace' ) { ?>
    <!-- <br>
    <br>
    <br> -->
    <h3 class="mt-5 mb-4">URL management</h3>

    <a href="<?=base_url('link/create'); ?>" class="btn btn-success"><i class="bi bi-plus-circle"></i> New link</a>

    <div class="row g-0 mt-4 me-3" >
        <div class="col-sm-4 overflow-auto bg bg-white border shadow" style="min-height:650px; max-height:650px" >
            <?= $this->renderSection('list-short-links') ?>
        </div>
        <?= csrf_field()?>

        <div id="container-show" class="col-sm-8 bg bg-white border shadow overflow-auto" style="min-height:650px; max-height:650px">

            <div class="alert alert-primary m-4" role="alert">
                <i class="bi bi-exclamation-triangle-fill"></i> No link selected
            </div>
        </div>
    
    </div>


<?php  }elseif($controller == 'createLinkForm' ){ ?>
    <?= $this->renderSection('create-link') ?>
<?php }elseif($controller == 'public'){?>
    <?= $this->renderSection($controller) ?>
    <?php }elseif($controller == 'editLinkForm'){ ?>
    <?= $this->renderSection('edit-link') ?>
    <?php }elseif($controller == 'list-users'){ ?>
    <?= $this->renderSection($controller) ?>
    <?php }elseif($controller == "user-create"){ 
        $this->renderSection($controller);
    }elseif($controller == "user-edit"){
        $this->renderSection($controller);
    }elseif($controller == "news_boot_css"){
        $this->renderSection('explorer');
        $this->renderSection($controller);
    }?>
    
    
</div>


<div class="mt-5">
    <?=view('Views/templates/_footer')?>
</div>


<script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.10.2/dist/umd/popper.min.js" integrity="sha384-7+zCNj/IqJ95wo16oMtfsKbZ9ccEh31eOz1HGyDuCQ6wgnyJNSYdrPa03rtR1zdB" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.min.js" integrity="sha384-QJHtvGhmr9XOIpI6YVutG+2QOK9T+ZnN4kzFN1RtK3zEFEIsxhlmWl5/YESvpZ13" crossorigin="anonymous"></script>

</body>
</html>