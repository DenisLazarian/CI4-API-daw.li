<?php

namespace App\Database\Seeds;

use CodeIgniter\Database\Seeder;
use Myth\Auth\Entities\User;

class AddAuthUsers extends Seeder
{
    public function run()
    {
        $authorize = $auth = service('authorization');
        $users = model(UserModel::class);
        $groups = model(GroupsModel::class);

        $row = [
            'active'   => 1,
            'password' => '1234',
            'username' => 'admin',
            'email' => 'admin@me.local',
            'name' => 'Josep M',
            'surname' => 'FR',
            'alias' => 'JmFXR',
        ];
        $user = new User($row);
        $userId = $users->insert($user);
        $authorize->addUserToGroup($userId, 'admin');
        $authorize->addUserToGroup($userId, 'user');
       
       
        $user->username= 'user';
        $user->email = 'user@me.local';
        $user->name = 'Angels';
        $user->surname = 'Cerveró';
        $user->alias = 'Angels';
       
        $userId = $users->insert($user);
        $authorize->addUserToGroup($userId, 'user');
       
        $user->username= 'convidat';
        $user->email = 'convidat@me.local';
        $user->name = 'Andreu';
        $user->surname = 'Ribes';
        $user->alias = 'Andreu Ribes';
       
        $userId = $users->insert($user);
        $authorize->addUserToGroup($userId, 'editor');
        $authorize->addUserToGroup($userId, 'user');


        $user->username= 'admin2';
        $user->email = 'admin@me.local';
        $user->name = 'Andreu';
        $user->surname = 'Lara';
        $user->alias = 'Lara Ribes';
        $user->active = 0;
       
        $userId = $users->insert($user);
        $authorize->addUserToGroup($userId, 'admin');
}
}