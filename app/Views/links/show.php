<input type="hidden" name="<?= csrf_token() ?>" value="<?= csrf_hash() ?>" />


<div id="container-show" class="m-4">
    <?php if(isset($link['id'])){?>
      <div class="card">
        <div class="card-header" <?= !$disabled ? "style='background: #ADF9A5'":"style='background: #F5DEE1'" ?> >
          <?= $disabled ? "Disabled":"Enabled"; ?>
        </div>
        <div class="card-body">
          <div class="d-flex gap-2"   >
            <h5 class="card-title fs-bold"> <a    href="<?=base_url('daw.li/'.str_replace(base_url('daw.li/'),'',$link['short_link']))?>" class="text-decoration-none <?= $disabled ? "disabled text-secondary":"" ?>"><?=$link['short_link']; ?></a> </h5> 
            <i  class="bi bi-clipboard-plus-fill text-secondary " ></i>
          </div>
          <small class="text-secondary"><?=$date_created ?> <?=isset($user['username']) ? "by <strong>".$user['username']."</strong>":""; ?> </small>
          
          <!-- <p class="card-text">With supporting text below as a natural lead-in to additional content.</p> -->
          <!-- <a href="#" class="btn btn-primary">Go somewhere</a> -->
        </div>
        <div class="card-footer  d-flex gap-2 justify-content-end">
          <div>
            <a href="<?=base_url('link/edit/'.$link['id'])?>" class="btn btn-primary">Edit</a>
          </div>
          <!-- <a href="delete" class="btn btn-danger">Delete</a> -->
          <form action="<?=base_url('link/delete/'.$link['id'])?>" method="post">
            <?=csrf_field(); ?>
            <button type="submit" class="btn btn-danger" >Delete</button>
          </form>
        </div>
      </div>


      <div class="card mt-4">
        
        <div class="card-body">
          <div class="d-flex gap-2">
            <h5 class="card-title fs-bold"> <span class="text-decoration-none"><?=$link['name'] ?? $link['short_link'] ; ?></span> </h5> 
          </div>
          <div class="mb-3">
            <small class="text-secondary "><?=$link['full_link']; ?></small>
          </div>
          <small class="text-secondary"><?=$link['expiration_date'] ? "<strong>Expiration date:</strong> ".date( 'F j, Y g:i A \G\M\TO',strtotime($link['expiration_date'])) : ""  ?> </small>
          
          <div class="mt-3 fw-bold">
            Statistics 
            <a data-bs-toggle="collapse" href="#info-stadistics" role="button" aria-expanded="false" aria-controls="info-stadistics" >
              <i class="bi bi-patch-question-fill"></i>
            </a>


            <div class="alert alert-primary collapse mt-2" id="info-stadistics">
          In this section, you can select a date range, and it will return the number of clicks or redirects your link has received within the specified date range. Click on the calculate button to execute the operation.
            </div>

            <div class="bg-light container mt-4">
              <div class="row">
                <div class="col-sm-6">
                  <label  for="fechaIni">Initial date:</label>
                  <div class="mb-3">
                    <input class="form-control" style="width:230px" type="date" name="fechaIni" id="fechaIni">
                  </div>
    
                  <label  for="fechaFinal">Initial date:</label>
                  <div>
                    <input class="form-control" style="width:230px" type="date" name="fechaFinal" id="fechaFinal">
                  </div>

                  <input onclick="getClicks(event);" type="button" value="Calculate"  class="btn btn-success w-100 mt-5">

                </div>
                <div id="click-result" class="col-sm-6 rounded border-2" style="background: #D0EBF6">
                  RESULT:

                  <div class="fw-bolt fs-4 mt-2">
                    0
                  </div>


                </div>

              </div>
            </div>

            <div>

            </div>
          </div>

        </div>


      </div>

      <script>

        function getClicks(e){
        $("click-result").html('<div class="text-center mt-4">cargando...</div>');

        var csrfToquen = document.createElement("input");
        csrfToquen.setAttribute("type", "hidden");
        csrfToquen.setAttribute("name", "<?= csrf_token() ?>");
        csrfToquen.setAttribute("value", "<?= csrf_hash() ?>");
        document.getElementById("container-show").appendChild(csrfToquen);

        var csrfToken = $('input[name="<?= csrf_token() ?>"]').val();

        $.ajax({
            // la URL para la petición
            url : '<?=base_url('link/result')?>',

            // la información a enviar
            // (también es posible utilizar una cadena de datos)
            data : { 
              linkId: <?=$link['id']?>,
              dateIni: $("#fechaIni").val(), 
              dateFinal: $("#fechaFinal").val() ,   
              // "<?= csrf_token() ?>": csrfToken,
              controller: "ajaxResultClicks"
            },

            // especifica si será una petición POST o GET
            type : 'GET',

            // el tipo de información que se espera de respuesta
            dataType : 'json',

            // código a ejecutar si la petición es satisfactoria;
            // la respuesta es pasada como argumento a la función
            success : function(json) {
              console.log("conseguido");
            //     $('<h1/>').text(json.title).appendTo('body');
            //     $('<div class="content"/>')
            //         .html(json.html).appendTo('body');
            },

            // código a ejecutar si la petición falla;
            // son pasados como argumentos a la función
            // el objeto de la petición en crudo y código de estatus de la petición
            error : function(xhr, status) {
                console.log('Disculpe, existió un problema');
            },

            // código a ejecutar sin importar si la petición falló o no
            complete : function(xhr, status) {
                console.log('Petición realizada');
                $("#click-result").html(xhr.responseText);
            }
        });

        csrfToquen.remove();
      }
      </script>
      

    <?php }else{?>

      <div class="alert alert-primary" role="alert">
      <i class="bi bi-exclamation-triangle-fill"></i> No link selected
      </div>

    <?php } ?>
      
</div>
