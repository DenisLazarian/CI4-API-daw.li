<?php $pager->setSurroundCount(5) ?>


<nav class="mt-3">
    <ul class="pagination">
    <?php if ($pager->hasPreviousPage()) : ?>
                <li class="page-item">
                    <a class="page-link" href="<?= $pager->getFirst() ?>">&lt;&lt;</a>
                </li>
                <li class="page-item">
                    <a class="page-link" href="<?= $pager->getPreviousPage() ?>">&lt;</a>
                </li>
            <?php else : ?>
                <li class="page-item">
                    <a href="#" class="page-link " disabled> &lt;&lt;</a>
                </li>
                <li class="page-item">
                    <a href="#" class="page-link " disabled> &lt;</a>
                </li>
            <?php endif ?>
        
            <?php foreach ($pager->links() as $link) : ?>
                <li  <?= $link['active'] ? 'class="page-item active"' : 'class="page-item"' ?>>
                    <a class="page-link" href="<?= $link['uri'] ?>"><?= $link['title'] ?></a>
                </li>
                
            <?php endforeach ?>
        
            <?php if ($pager->hasNextPage()) : ?>
                <li class="page-item">
                    <a class="page-link" href="<?= $pager->getNextPage() ?>">&gt;</a>
                </li>
                <li class="page-item">
                    <a class="page-link" href="<?= $pager->getLast() ?>">&gt;&gt;</a>
                </li>
            <?php else : ?>
                <li class="page-item"> <a href="#" disabled class=" page-link ">
                    &gt;
                    </a> 
                </li>
                <li class="page-item"> <a href="#" disabled class="page-link ">
                    &gt;&gt;    
                    </a> </li>
            <?php endif ?>
        </ul>
</nav>