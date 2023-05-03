<?php

namespace App\Database\Seeds;

use CodeIgniter\Database\Seeder;

class LinkSeeder extends Seeder
{
    public function run()
    {
        $modelLink = model('LinkModel');
        $modelUser = model('UserModel');

        $users = $modelUser->findAllUsers();

        foreach ($users as $user) {
            for ($i=0; $i < 5; $i++) { 
                # code...
                $data = [
                    'user_id' => $user->id,
                    'full_link' => 'http://www.youtube.com',
                    'short_link' => base_url('daw.ly/youtube'),
                    'description' => 'Google',
                    'created_date' => date('Y-m-d H:i:s'),
                    // 'updated_at' => date('Y-m-d H:i:s'),
                ];
                $modelLink->addLink($data);
            }
        }
    }
}
