<?php

namespace App\Controllers;

use App\Models\GroupsModel;
use App\Models\LinkModel;
use App\Models\LoginModel;
use App\Models\UserModel;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\RESTful\ResourceController;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Myth\Auth\Entities\User;
use Myth\Auth\Password;

use Myth\Auth\Config\Auth as AuthConfig;



class LinksApiController extends ResourceController
{

    protected $auth;

    /**
     * @var AuthConfig
     */
    protected $config;

    protected $validate;

    

    public function __construct()
    {
        // Most services in this controller require
        // the session to be started - so fire it up!

        $this->config = config('Auth');
        $this->auth   = service('authentication');
        $this->validate = \Config\Services::validation();
    }



    /**
     * Return an array of resource objects, themselves in array format
     *
     * @return mixed
     */
    public function index()
    {
        $model = new \App\Models\LinkModel();

        $links = $model->findAllLinks();

        $responses = [
            'status' => 200,
            'error' => false,
            'messages' => 'Links Found',
            'data' => $links
        ];

    }

    /**
     * Return the link of a resource object
     *
     * @return mixed
     */
    public function getSingleURL($id)
    {
        $model = new \App\Models\LinkModel();

        $link = $model->getSingleURL($id);

        if($link ?? false){
            $response= [
                'status' => 200,
                "error" => false,
                'messages' => 'Link found',
                'data'=> $link
            ];
        }else{
            $response= [
                'status' => 404,
                "error" => true,
                'messages' => 'Link not found',
                'data'=> $link
            ];
        }

        return $this->respond($response);
    }

    /**
     * Return the properties of a resource object
     *
     * @return mixed
     */
    public function show($id = null)
    {
        $model = new \App\Models\LinkModel();

        $link = $model->findLink($id);

        if($link ?? false){
            $response= [
                'status' => 200,
                "error" => false,
                'messages' => 'Link found',
                'data'=> $link
            ];
        }else{
            $response= [
                'status' => 404,
                "error" => true,
                'messages' => 'Link not found',
                'data'=> $link
            ];
        }

        return $this->respond($response);
    }

    /**
     * Return a new resource object, with default properties
     *
     * @return mixed
     */
    public function new()
    {
        
    }

    /**
     * Create a new resource object, from "posted" parameters
     *
     * @return mixed
     */
    public function create()
    {
        //
    }

    public function createNotRegistered(){
        $model = new \App\Models\LinkModel();

        $data = $this->request->getJSON();

        $link = $model->addLink($data);

        if($link ?? false){
            $response= [
                'status' => 200,
                "error" => false,
                'messages' => 'Link created',
                'data'=> $link
            ];
        }else{
            $response= [
                'status' => 404,
                "error" => true,
                'messages' => 'Link not created',
                'data'=> $link
            ];
        }

        return $this->respond($response);
    }

    /**
     * Return the editable properties of a resource object
     *
     * @return mixed
     */
    public function edit($id = null)
    {
        //
    }

    /**
     * Add or update a model resource, from "posted" properties
     *
     * @return mixed
     */
    public function update($id = null)
    {
        //
    }

    /**
     * Delete the designated resource object from the model
     *
     * @return mixed
     */
    public function delete($id = null)
    {
        //
    }

   

    /**
     * API Sample call
     *
     */
    public function test()
    {
        // Get current token payload as object
        $token_data = json_decode($this->request->header("token-data")->getValue());
        // dd($token_data);
        // Get current config for this controller request as object
        // $token_config = json_decode($this->request->header("token-config")->getValue());
       
        // Get JWT policy config
        // $policy_name = $this->request->header("jwt-policy")->getValue();

        // check if user has permission or token policy is ok
        // if user no authorizedk
        //      $this->fail("User no valid")

        $response = [
            'status' => 200,
            'error' => false,
            'messages' => 'Test function ok',
            'data' => [
                "data" => time(),
                "token-username" => $token_data->name,
                "token-email" => $token_data->email,
            ]
        ];
        return $this->respond($response);
    }

    /**
     * Login API to generate JWT token
     *
     */
    public function login()
    {
        helper(["form"]);

        $auth = service("authentication");

        $rules = [
            'email' => 'required',
            'password' => 'required|min_length[4]'
        ];
        if (!$this->validate($rules)) return $this->fail($this->validator->getErrors());
        $model = new UserModel();
        $user = $model->getUserByMailOrUsername($this->request->getVar('email'));

        if (!$user) return $this->failNotFound('Email Not Found');
        // d($user['username']);
        // d($user['email']);
        // d($this->request->getVar('password'));
        // d($user['password_hash']);

        $credentials = [
            'email'=> $user['email'],
            'password'=>$this->request->getVar('password')
        ];

        $verify = $auth->attempt($credentials, true);

        // dd($verify);

        if (!$verify) return $this->fail('Wrong Password or the account is not activated, in second case wait an admin to activate your account');

        /****************** GENERATE TOKEN ********************/
        helper("jwt");

        $APIGroupConfig = "test";
        $cfgAPI = new \Config\APIJwt($APIGroupConfig);

        $data = array(
            "uid" => $user['id'],
            "name" => $user['username'],
            "email" => $user['email']
        );

        $token = newTokenJWT($cfgAPI->config(), $data);
        /****************** END TOKEN GENERATION **************/

        $response = [
            'status' => 200,
            'error' => false,
            'messages' => 'User logged In successfully',
            'token' => $token
        ];

        return $this->respond($response);
        
    }

    public function getAllUsersApi(){

        $userModel = new UserModel();
        $loginModel = new LoginModel();

        $userList = $userModel->findAllUsers();
        
        if($userList ?? false){
            $response = [
                'status' => 200,
                'error' => false,
                'messages' => 'List of users',
                'users' => $userList
            ];
        }else{
            $response = [
                'status' => 404,
                'error' => true,
                'messages' => 'No users found',
                // 'users' => $userList
            ];
        }


        return $this->respond($response);
        
    }

    public function getUserRoles($idUser){

        $userModel = new UserModel();

        $groupsModel = new GroupsModel();

        $groupSet = $groupsModel->getGroupsForUser($idUser);
        // d($groupSet);

        $roles =  ['message'=>"no roles"];
        
        for ($i=0; $i < count($groupSet); $i++) { 
            $roles[$i] = [
                "id" => $groupSet[$i]['group_id'],
                "name" => $groupSet[$i]['name']
            ];
        }

        // dd($roles);

        $userSet = $userModel->findUser($idUser);

        $userSet['roles'] = $roles ;


        $response = [
            'status' => 200,
            'error' => false,
            'messages' => 'List of roles',
            
            'user' => $userSet
        ];


        return $this->respond($response);
    }


    public function editUser($idUser){

        $header = $this->request->header("Authorization");
        // $header = $request->headers();

        $token = null;


        // Mediante el token JWT obtenemos el id del usuario logueado
        if (!empty($header)) {
            if (preg_match('/Bearer\s(\S+)/', $header, $matches)) {
                $token = $matches[1];
            }
        }
        $cfgAPI = new \Config\APIJwt(); // configuracion i algoritmo de decodificacion

        $token_data = JWT::decode($token, new Key($cfgAPI->config()->tokenSecret, $cfgAPI->config()->hash)); // para pillar el id lo decodificamos con la libreria.

        $userModel = new UserModel();
        $groupModel = new GroupsModel();

        $userLogged = $userModel->findUser($token_data->uid);

        if(!$userModel->inGroup('1', $userLogged['id'])){

            if($userLogged['id'] != $idUser) 
                return $this->fail('User not authorized to edit this user');
            
        }

        $email = $this->request->getVar("email");
        $username = $this->request->getVar("username");
        $active = $this->request->getVar("active");
        $password_hash = $this->request->getVar("password_hash");

        $data= [
            'email' => $email,
            'username' => $username,
            'active' => $active,
            'password_hash'=> Password::hash($password_hash)
        ];

        
        if(!$password_hash || $password_hash == "") 
            unset($data['password']);
        
        // $user = new User($data);

        $userModel = model(UserModel::class);

        $userModel->updateUser($data, $idUser);

        $userEdited = $userModel->findUser($idUser);

        $response = [
            'status' => 200,
            'error' => false,
            'messages' => 'User updated with exit',
            'updated_at' => date('Y-m-d H:i:s'),
            'user' => $userEdited,
        ];

        return $this->respond($response);

    }



    public function checkUserRole($idUser, $idRole){

        $userModel = model(UserModel::class);
        $roleModel = model(GroupsModel::class);

        $userSet = $userModel->findUser($idUser);

        $role = $roleModel->getRoleById($idRole);

        $userRoleValidate = $userModel->inGroup($idRole, $idUser);

        $response = [
            'status' => 200,
            'error' => false,
            'messages' => 'User roles',
            'user' => $userSet,
        ];

        $response['user']['roles'] = $userRoleValidate ? "TRUE: The user have rol ". $role["name"] : "FALSE: The user don't have rol ". $role["name"];

        return $this->respond($response);

        // $userModel->inGroup('1', $idUser);
    }


    public function registerUserApi(){

        $response = [];

        // d($this->request->getVar("password"));
        // d($this->request->getVar("username"));
        // dd($this->request->getVar("email"));

        if (! $this->config->allowRegistration) {
            $response = [
                'status' => 401,
                'error' => true,
                'messages' => lang('Auth.registerDisabled'),
            ];
            return $this->respond($response);
        }

        $users = model(UserModel::class);

        // Validate basics first since some password rules rely on these fields
        $rules = config('Validation')->registrationRules ?? [
            'username' => 'required|alpha_numeric_space|min_length[3]|max_length[30]|is_unique[users.username]',
            'email'    => 'required|valid_email|is_unique[users.email]',
        ];

        if (! $this->validate($rules)) {
            $response = [
                'status' => 401,
                'error' => true,
                'messages' =>  $this->validator->getErrors(),
            ];
            return $this->respond($response);
        }

        // Validate passwords since they can only be validated properly here
        $rules = [
            'password'     => 'required',
            'pass_confirm' => 'required|matches[password]',
        ];

        if (! $this->validate($rules)?? false) {
            $response = [
                'status' => 401,
                'error' => true,
                'messages' =>  $this->validator->getErrors(),
            ];
            return $this->respond($response);
        }

        // Save the user
        $allowedPostFields = array_merge(['password'], $this->config->validFields, $this->config->personalFields);
        $user = new User($this->request->getVar($allowedPostFields));
        

        $this->config->requireActivation === null ? $user->activate() : $user->generateActivateHash();

        // Ensure default group gets assigned if set
        if (! empty($this->config->defaultUserGroup)) {
            $users = $users->withGroup($this->config->defaultUserGroup);
        }
        

        if (! $users->save($user)) {
            $response = [
                'status' => 401,
                'error' => true,
                'messages' =>  $this->validator->getErrors(),
            ];
            return $this->respond($response);
            // return redirect()->back()->withInput()->with('errors', $users->errors());
        }

        $user = $users->getUserByMailOrUsername($user->email);
        $groups = model(GroupsModel::class);

        $groups -> addUserToGroup($user['id'], 2);


        if ($this->config->requireActivation !== null) {
            $activator = service('activator');

            // Success!
            $response = [
                'status' => 200,
                'error' => false,
                'messages' =>  lang('Auth.waitAdministrator') ,
                'user' => $user,
            ];
            return $this->respond($response);

        }
        // Success!
        $response = [
            'status' => 200,
            'error' => false,
            'messages' =>  lang('Auth.registerSuccess'),
            'user' => $user,
        ];
        return $this->respond($response);
    }


    public function createDawlyApi(){
        $linkModel =  model(LinkModel::class);

        $header = $this->request->header("Authorization");
        // $header = $request->headers();

        $token = null;

        // dd($header);
        // Mediante el token JWT obtenemos el id del usuario logueado
        if (!empty($header)) {
            if (preg_match('/Bearer\s(\S+)/', $header, $matches)) {
                $token = $matches[1];
            }
        }
        $cfgAPI = new \Config\APIJwt(); // configuracion i algoritmo de decodificacion

        $token_data = JWT::decode($token, new Key($cfgAPI->config()->tokenSecret, $cfgAPI->config()->hash)); // para pillar el id lo decodificamos con la libreria.

        $link = $this->request->getVar('destination');
        $linkShort = $this->request->getVar('short-url');
        $linkFile = $this->request->getVar('associate-file');

        
        
        $title = $this->request->getVar('title');
        $description = $this->request->getVar('description');
        

        if($title == "")
            $title = null;
        
        if($description == "")
            $description = null;

        $expirationDate = $this->request->getVar('expiration-date');

        if($expirationDate == "")
            $expirationDate = null;

        

        $linkShort =  $linkModel->getRandomTitle($linkShort);

        
        $sLink = base_url('daw.li/'.$linkShort);

        $validationRules =
            [
                'destination' => [
                    'label'  => 'Destination',
                    'rules'  => 'required',     // |valid_email',
                    'errors' => [
                        'required' => 'The url destination is required',
                        
                    ],
                ],

            ];

        if(!$this->validate($validationRules)){
            // dd("algo");
            $errors = $this->validator->getErrors();
            // dd($errors);
            
            $response = [
                'status' => 401,
                'error' => true,
                'messages' =>  $errors,
            ];
            
            return $this->respond($response);
        }
        // dd($expirationDate);
        $link = $linkModel->addLink([
            'full_link' => $link,
            'short_link' => $sLink,
            'user_id' => $token_data->uid ?? null,
            'name' => $title,
            'description' => $description,
            'created_date' => date('Y-m-d H:i:s'),
            // 'updated_at' => date('Y-m-d H:i:s'),
            'expiration_date' => $expirationDate,
            // 'is_file'   =>  ($linkFile ?? false)?true:false
        ]);
        
        $link = $linkModel->findLink($link);
        
        $data=[
            // 'title'=>"Public Site",
            // 'controller'=>"public",
            // 'long_link'=>$link['full_link'],
            // 'link'=>$link ? base_url("daw.li/".$linkShort): "Error",
            // 'url_link' => base_url("daw.li/".$linkShort),
            'Info' => $link
        ];

        $response = [
            'status' => 401,
            'error' => true,
            'messages' =>  "Link created successfully",
            'Link created' => $data,
        ];
        
        return $this->respond($response);


        // return view('links/public',$data);

    }

    public function editDawlyApi($linkId){
        $userModel =  model(UserModel::class);
        $linkModel =  model(LinkModel::class);
        

        $header = $this->request->header("Authorization");
        // $header = $request->headers();

        $token = null;

        // dd($header);
        // Mediante el token JWT obtenemos el id del usuario logueado
        if (!empty($header)) {
            if (preg_match('/Bearer\s(\S+)/', $header, $matches)) {
                $token = $matches[1];
            }
        }
        $cfgAPI = new \Config\APIJwt(); // configuracion i algoritmo de decodificacion

        $token_data = JWT::decode($token, new Key($cfgAPI->config()->tokenSecret, $cfgAPI->config()->hash)); // para pillar el id lo decodificamos con la libreria.
        
        $linkToUpdate = $linkModel->findLink($linkId);

        if($linkToUpdate == null){
            $response = [
                'status' => 401,
                'error' => true,
                'messages' =>  "Link not found",
            ];
            return $this->respond($response);
        }

        if(!$userModel->inGroup(1, $token_data->uid)){ // si es admin, continuamos, si no lo es, comprovamos si es suyo el link

            $linkByUser = $linkModel->findLinkByUserAndID($token_data->uid, $linkId) ? $linkModel->findLinkByUserAndID($token_data->uid, $linkId)['user_id'] : -1;
           

            if($linkToUpdate['user_id'] != ($linkByUser)){
                $response = [
                    'status' => 401,
                    'error' => true,
                    'user'  => $token_data->uid,
                    'link'  => $linkId,
                    'messages' =>  "You don't have permission to edit this link",
                ];
                return $this->respond($response);
            }
        }

        $link = $this->request->getVar('destination');
        $linkShort = $this->request->getVar('short-url');
        $title = $this->request->getVar('title');
        $description = $this->request->getVar('description');
        $expirationDate = $this->request->getVar('expiration-date');
        

        if($title == "")
            $title = null;
        
        if($description == "")
            $description = null;

        if($expirationDate == "")
            $expirationDate = null;

        
            
        $linkShort =  $linkModel->getRandomTitle($linkShort);

        // processo para editar el link

        $data = [
            'name' => $title ,
            'description' => $description,
            'expiration_date' => $expirationDate,
            'full_link' => $link,
            'short_link' => $linkShort,
        ];

        $linkUpdated = $linkModel->updateLink($linkId, $data);

        // dd($linkUpdated);

        $linkUpdated = $linkModel->findLink($linkUpdated);

        $response =[
            'status' => 200,
            'error' => false,
            'messages' =>  "Link updated successfully",
            'user'  => $token_data->uid,
            'Link updated' => $linkUpdated,
        ];
        

        return $this->respond($response);
    }
}
