<?php

namespace App\Database\Seeds;

use CodeIgniter\Database\Seeder;

class ClickSeeder extends Seeder
{
    public function run()
    {
        
        $modelClick = model('ClickModel');
        $modelLink = model('LinkModel');


        $links = $modelLink->findAllLinks();

        foreach ($links as $link) {
            for ($i=0; $i < 5; $i++) { 
                # code...
                $data = [
                    'link_id' => $link['id'],
                    'date' => date('Y-m-d'),
                ];
                $modelClick->insert($data);
            }
        }
    }
}
