<?php

namespace App\Database\Seeds;

use CodeIgniter\Database\Seeder;

class AddAuthGroups extends Seeder
{
    public function run()
    {
        $authorize = $auth = service('authorization');
        $authorize->createGroup('admin', 'Usuaris administradors del sistema');
        $authorize->createGroup('user','Usuaris generals');
        $authorize->createGroup('editor', 'Usuaris convidats');
        $authorize->createGroup('relleno', 'Usuaris convidats');
        $authorize->createGroup('rol de preuba', 'Usuaris convidats');
    }
}
