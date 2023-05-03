<?php

namespace App\Database\Seeds;

use CodeIgniter\Database\Seeder;

class Install extends Seeder
{
    public function run()
    {
        $this->call('AddAuthUsers');
        $this->call('AddAuthGroups');
        $this->call('linkSeeder');
        $this->call('ClickSeeder');

    }
}
