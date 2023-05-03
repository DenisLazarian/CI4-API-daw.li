<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use App\Models\UserModel;
// use Myth\Auth\Models\UserModel;

class UserController extends BaseController
{
    

    public function list(){
        $userModel = new UserModel();
        // $users = $userModel->findAllUsers();
        $data = [
            'title' => 'List Users',
            'users' => $userModel->paginate(5),
            'controller' => 'list-users',
            'pager' => $userModel->pager
            
        ];
        return view('users/list', $data);
    }

    public function edit(){
        $userModel = new UserModel();
        $userGroupModel = new \App\Models\GroupsModel();

        
        $id = $this->request->uri->getSegment(3);

        $user = $userModel->findUser($id);
        $groups = $userGroupModel->findAllGroups();

        $groupsVal = [];
        foreach ($groups as $key => $value) {
            
            if($userModel->inGroup($value['id'], $id)){
                $groupsVal[$key]['checked'] = true;
            }else{
                $groupsVal[$key]['checked'] = false;
            }

        }
        // dd($groupsVal);

        $data = [
            'title' => 'Edit User',
            'user' => $user,
            'controller' => 'user-edit',
            'groups' => $groups,
            'groupsVal' => $groupsVal
        ];

        return view('users/edit', $data);
    }

    public function update($id){
        $userModel = new UserModel();

        $groupModel = new \Myth\Auth\Models\GroupModel();

        $allRequests = $this->request->getRawInput();
        // dd($allRequests);
        $validationRules = [
            
            'email' => [
                'label'  => 'email',
                'rules'  => 'required|valid_email',     // |valid_email',
                'errors' => [
                    'required' => "It's required",
                    'valid_email' => 'Email not valid'
                ],
            ],
            'password' => [
                'label'  => 'pass',
                'rules'  => 'min_length[8]',     
                'errors' => [
                    // 'required' => "It's required",
                    'min_length' => 'Password must be at least 8 characters'
                ],
            ],
            'passconf' => [
                'label'  => 'pass',
                'rules'  => 'matches[password]',     
                'errors' => [
                    // 'required' => "It's required",
                    'matches[password]' => 'Password not matches'
                ],
            ],
        ];
        if(!$this->request->getPost('password') ?? true){ // si hay contraseña, se pone, si no, dejamos la antigua
        
            $validationRules = [
            
                'email' => [
                    'label'  => 'email',
                    'rules'  => 'required|valid_email',     // |valid_email',
                    'errors' => [
                        'required' => "It's required",
                        'valid_email' => 'Email not valid'
                    ],
                ]
                
            ];
        }
        


        if(!$this->validate($validationRules)){
            
            $errors = $this->validator->getErrors();
            // dd($errors);
            if($errors['email'] ?? false) session()->setFlashdata('errorMail', $errors['email']);
            if($errors['password'] ?? false) session()->setFlashdata('errorPass', $errors['password']);
            if($errors['passconf'] ?? false) session()->setFlashdata('errorConf', $errors['passconf']);
            
            // $userModel->saveUser($data);
            return redirect()->to(base_url('admin/create'));
        }

        if($this->request->getPost('password') ?? false){ // si hay contraseña, se pone, si no, dejamos la antigua
            $data = [
                'password_hash' => password_hash($this->request->getPost('password'),PASSWORD_DEFAULT),
            ];
        }

        $data = [
            'username' => $this->request->getPost('username'),
            'email' => $this->request->getPost('email'),
            'active' => $this->request->getPost('active')?? 0,
            'updated_at' => date('Y-m-d H:i:s'),
        ];

        // assignar grupo

        $user = $userModel->updateUser($data, $id);

        foreach ($this->request->getRawInput() as $key => $value) {
            if((strstr($key,'_role'))) {
                $arrayKey = explode('-', $key); // 0 => role, 1 => id
                // $addResponse = $groupModel->addUserToGroup(intval($user), intval($arrayKey[1])); //userId - groupId
                $checkBox = str_replace('_','', $key); // comprobamos si el checkbox está marcado

                if(isset($allRequests[$checkBox]) && $value=="false"){
                    $addResponse = $groupModel->addUserToGroup($id, intval($arrayKey[1])); //userId - groupId
                }elseif(!(isset($allRequests[$checkBox])) && $value=="true"){
                    $addResponse = $groupModel->removeUserFromGroup($id, intval($arrayKey[1])); //userId - groupId
                }
            }
        }
        

        return redirect()->to(base_url('admin'));
    }

    public function delete($id){

        session()->start();
        if(session('user')->id != $id){
            $userModel = new UserModel();
            $userModel->deleteUser($id);
        }else
            session()->setFlashdata('error', 'You can not delete yourself');
        

        return redirect()->to(base_url('admin'));
    }

    public function disable($id){
        session()->start();
        if(session('user')->id != $id){
            $userModel = new UserModel();
            $userModel->disableUser($id);
        }else
            session()->setFlashdata('error', 'You can not disable yourself');

        
        return redirect()->to(base_url('admin'));
    }

    public function create()
    {

        $userGroupModel = new \App\Models\GroupsModel();
        $groups = $userGroupModel->findAllGroups();
        $data = [
            'title' => 'Create User',
            'controller' => 'user-create',
            'groups' => $groups
        ];

        return view('users/create', $data);
    }

    public function save(){
        $userModel = new UserModel();

        $groupModel = new \Myth\Auth\Models\GroupModel();

        // dd($this->request->getRawInput());
        $validationRules = [
            
            'email' => [
                'label'  => 'email',
                'rules'  => 'required|valid_email',     // |valid_email',
                'errors' => [
                    'required' => "It's required",
                    'valid_email' => 'Email not valid'
                ],
            ],
            'password' => [
                'label'  => 'pass',
                'rules'  => 'required|min_length[8]',     // |valid_email',
                'errors' => [
                    'required' => "It's required",
                    'min_length' => 'Password must be at least 8 characters'
                ],
            ],
            'passconf' => [
                'label'  => 'pass',
                'rules'  => 'required|matches[password]',     // |valid_email',
                'errors' => [
                    'required' => "It's required",
                    'matches[password]' => 'Password not matches'
                ],
            ],
        ];


        if(!$this->validate($validationRules)){
            
            $errors = $this->validator->getErrors();
            // dd($errors);
            if($errors['email'] ?? false) session()->setFlashdata('errorMail', $errors['email']);
            if($errors['password'] ?? false) session()->setFlashdata('errorPass', $errors['password']);
            if($errors['passconf'] ?? false) session()->setFlashdata('errorConf', $errors['passconf']);
            
            // $userModel->saveUser($data);
            return redirect()->to(base_url('admin/create'));
        }

        

        $data = [
            'username' => $this->request->getPost('username'),
            'email' => $this->request->getPost('email'),
            'password_hash' => password_hash($this->request->getPost('password'),PASSWORD_DEFAULT),
            'active' => $this->request->getPost('active')??0,
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s'),
        ];

        // assignar grupo

        $user = $userModel->newUser($data);

        foreach ($this->request->getRawInput() as $key => $value) {
            if(strstr($key,'role') && !(strstr($key,'_role'))) {
                $arrayKey = explode('-', $key); // 0 => role, 1 => id
                $addResponse = $groupModel->addUserToGroup(intval($user), intval($arrayKey[1])); //userId - groupId
            }
        }
        

        return redirect()->to(base_url('admin'));
    }
    

}
