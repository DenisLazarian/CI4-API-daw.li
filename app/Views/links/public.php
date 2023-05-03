<?= $this->extend('Views/links/layout') ?>


<?= $this->section('public') ?> 

        
        <div class="container mt-3">

            <h1 class="mb-3">Welcome to daw.ly</h1>

            <p>Lorem ipsum dolor sit amet consectetur, adipisicing elit. Repellat, placeat! Aperiam dolore reprehenderit ad nulla. Nisi, error. Maxime unde illum deserunt magnam, eligendi est culpa facere illo dolor, velit consequatur.
            Minus fuga sequi laboriosam! Quam, voluptatibus. Odio sunt laboriosam consequuntur, maxime ullam dignissimos ipsam mollitia eos, ipsum pariatur hic sed doloremque assumenda. Officiis, sed! Numquam sed animi dicta laudantium quos.
            Ducimus adipisci nostrum quam quibusdam perspiciatis culpa voluptatem optio aperiam earum! Ipsam vero iusto quidem, corporis praesentium deserunt, deleniti sint error magni quam non quas aut saepe soluta, rem eum.
            Provident expedita asperiores minima dolores cupiditate facilis unde pariatur quasi quia fugiat quas a fugit, optio voluptas dolore veniam officiis consequatur saepe et. Nihil voluptatum, harum ullam assumenda excepturi ipsum.
            Dolore impedit minima veritatis nemo, alias temporibus dolores delectus doloribus ducimus porro sequi pariatur voluptatem voluptatibus ipsum esse quasi veniam aperiam qui et, fuga maiores. Eaque quia magnam quidem iste!</p>

            <h5 class="mt-4">Generate your free url:</h5>
            <div class="d-flex gap-2">

                <a class="btn btn-success mt-2 p-2" href="<?=base_url('link/create')?>"><i class="bi bi-plus-circle"></i> New link</a>
                <? d(session('dataLinks')) ?>
                <?php if(session('dataLinks') ?? false){ ?>
                
                <div class=" mt-2 p-1">
                    <button type="button" class="btn btn-primary " data-bs-toggle="modal" data-bs-target="#exampleModal">
                        <i class="bi bi-eye-fill"></i> <small> See url</small> 
                    </button>
                </div>

                <?php } ?>

            </div>
        </div>

        

        <!-- Modal -->

        <?php if(session('dataLinks') ?? false){ ?>
        
        
        
        <div class="modal fade" id="exampleModal" tabindex="-1" aria-labelledby="exampleModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="exampleModalLabel">Your free URL</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    
                    <div class="alert alert-warning">
                        <span>This link is for personal use or shared with limit uses and can only be viewed by authenticated users. It will be stored for one month. To access and manage your saved links, please <a href="<?=base_url('register')?>">register</a> on the website to obtain the following advantages:  
                        
                            <ul class="mt-2">
                                <li>Access to your saved links</li>
                                <li>Manage your links</li>
                                <li>Customize your links</li>
                                <li>Access to statistics</li>
                                <li>Have a file space</li>
                            </ul>


                        If you already have an account, please <a href="<?=base_url('login')?>">login</a> to access your links.
                        </span>
                    </div>
                    <div class="fw-bold">Your generated Link:</div>
                    <div class="alert alert-success mt-2">
                        <a href="<?=$link ?>" class="text-primary text-decoration-none">
                            <?=$url_link; ?>
                        </a>
                    </div>

                </div>
                <div class="modal-footer">
                    <!-- <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Ok</button> -->
                    <button type="button" class="btn btn-primary" data-bs-dismiss="modal">I understand</button>
                </div>
            </div>
        </div>
        </div>
        <?php } ?>
        


<?= $this->endSection() ?>

<?= $this->section('nom_seccio_contingut') ?> <?= $this->endSection() ?>

