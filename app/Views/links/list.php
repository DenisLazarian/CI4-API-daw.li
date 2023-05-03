<?= $this->extend('Views/links/layout') ?>



<?= $this->section('list-short-links') ?> 


    <ul class="p-0 ">
    
    
        <?php foreach ($links as $link) : 
            $disabled = ($link['expiration_date'] && ($link['expiration_date'] < date('Y-m-d'))) ;
            // d($disabled);
            ?>
            
            <div class=" p-3 border border-bottom border-secodnary    m-0  ms-0 <?=$disabled ? "alert alert-danger " : "bg bg-white" ?>  ">
                <div class="fs-5"><?=esc($link['name'] ?? $link['full_link']); ?></div>
                <div class="mt-3  <?= $disabled ? "text-decoration-line-through text-danger":"text-primary" ?>"><?=esc( $link['short_link']); ?></div>
                <div class="text-end">
                    <div class="btn-group m-0 mt-4">
                        <!-- <a href="" class=" link-danger text-decoration-none  m-2">Delete</a>
                        <a href="" class="btn btn-primary">Edit</a> -->
                        <button role="button" id="button_<?=$link['id']; ?>" class="clicable btn btn-<?=$disabled?'danger':'primary'?> ">Show</button>
                        <button type="button" class="btn btn-<?=$disabled?'danger':'primary'?> dropdown-toggle dropdown-toggle-split" data-bs-toggle="dropdown" aria-expanded="false">
                            <!-- <span class="visually-hidden">Toggle Dropdown</span> -->
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="<?=base_url('link/edit/'.$link['id']); ?>">Edit</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li>    
                                <form action="<?=base_url('link/delete/'.$link['id'])?>" method="post">
                                <?=csrf_field(); ?>
                                    <button type="submit" class="dropdown-item" >Delete</button>
                                </form>
                            </li>
                        </ul>
                    </div>

                </div>
                

            </div>
                <!-- <a  <?= $disabled ? 'class="text-decoration-line-through text-danger" onclick="return false"' : 'href="'.base_url('links/' . $link['short_link']) .'"'?> > <?= $link['short_link'] ?> </a> -->
        <?php endforeach; ?>

        <?php if(count($links) == 0){
            echo '<div class="alert alert-warning m-4" role="alert">
            <i class="bi bi-exclamation-triangle-fill"></i> No links found
            </div>';
        
        } ?>
        
        <script>

            

            document.querySelectorAll('.clicable').forEach((e)=>{
                e.addEventListener('click',(e)=>{
                    // console.log(e.target);
                    // console.log($('#container-show'));
                    const csrfToken = $('meta[name="csrf-token"]').attr('content');

                    $('#container-show').html('<div class="text-center mt-4">cargando...</div>');

                    $.ajax({
                        // la URL para la petición
                        url : '<?=base_url('link/show/'); ?>' + e.target.id.replace('button_',''),

                        // la información a enviar
                        // (también es posible utilizar una cadena de datos)
                        // data : { id : 123 },
                        data:{
                            // 'X-CSRF-TOKEN': csrfToken,
                        },
                        // especifica si será una petición POST o GET
                        type : 'GET',

                        // el tipo de información que se espera de respuesta
                        dataType : 'json',

                        // código a ejecutar si la petición es satisfactoria;
                        // la respuesta es pasada como argumento a la función
                        success : function(json) {
                            // $('<h1/>').text(json.title).appendTo('body');
                            // $('<div class="content"/>')
                            //     .html(json.html).appendTo('body');
                        },
                        // código a ejecutar sin importar si la petición falló o no
                        complete : function(xhr, status) {
                            console.log('Petición realizada');
                            $('#container-show').html(xhr.responseText);
                        }
                    });

                })
            })
        </script>
    </ul>


<?= $this->endSection() ?>
