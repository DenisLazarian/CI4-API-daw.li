<?php

namespace App\Models;

use CodeIgniter\Model;
use Faker\Generator;
use Myth\Auth\Authorization\GroupModel;
use Myth\Auth\Entities\User;

/**
 * @method User|null first()
 */
class UserModel extends Model
{
    protected $table          = 'users';
    protected $primaryKey     = 'id';
    protected $returnType     = 'App\Entities\User';
    protected $useSoftDeletes = true;
    protected $allowedFields  = [
        'email', 'username', 'password_hash', 'reset_hash', 'reset_at', 'reset_expires', 'activate_hash',
        'status', 'status_message', 'active', 'force_pass_reset', 'permissions', 'deleted_at',
    ];
    protected $useTimestamps   = true;
    protected $validationRules = [
        'email'         => 'required|valid_email|is_unique[users.email,id,{id}]',
        'username'      => 'required|alpha_numeric_punct|min_length[3]|max_length[30]|is_unique[users.username,id,{id}]',
        'password_hash' => 'required',
    ];
    protected $validationMessages = [];
    protected $skipValidation     = false;
    protected $afterInsert        = ['addToGroup'];

    /**
     * The id of a group to assign.
     * Set internally by withGroup.
     *
     * @var int|null
     */
    protected $assignGroup;

    /**
     * Logs a password reset attempt for posterity sake.
     */
    public function logResetAttempt(string $email, ?string $token = null, ?string $ipAddress = null, ?string $userAgent = null)
    {
        $this->db->table('auth_reset_attempts')->insert([
            'email'      => $email,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'token'      => $token,
            'created_at' => date('Y-m-d H:i:s'),
        ]);
    }

    /**
     * Logs an activation attempt for posterity sake.
     */
    public function logActivationAttempt(?string $token = null, ?string $ipAddress = null, ?string $userAgent = null)
    {
        $this->db->table('auth_activation_attempts')->insert([
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'token'      => $token,
            'created_at' => date('Y-m-d H:i:s'),
        ]);
    }

    /**
     * Sets the group to assign any users created.
     *
     * @return $this
     */
    public function withGroup(string $groupName)
    {
        $group = $this->db->table('auth_groups')->where('name', $groupName)->get()->getFirstRow();

        $this->assignGroup = $group->id;

        return $this;
    }

    /**
     * Clears the group to assign to newly created users.
     *
     * @return $this
     */
    public function clearGroup()
    {
        $this->assignGroup = null;

        return $this;
    }

    /**
     * If a default role is assigned in Config\Auth, will
     * add this user to that group. Will do nothing
     * if the group cannot be found.
     *
     * @param mixed $data
     *
     * @return mixed
     */
    protected function addToGroup($data)
    {
        if (is_numeric($this->assignGroup)) {
            $groupModel = model(GroupModel::class);
            $groupModel->addUserToGroup($data['id'], $this->assignGroup);
        }

        return $data;
    }

    /**
     * Faked data for Fabricator.
     */
    public function fake(Generator &$faker): User
    {
        return new User([
            'email'    => $faker->email,
            'username' => $faker->userName,
            'password' => bin2hex(random_bytes(16)),
        ]);
    }

    public function getUserLink($linkId){
        $query = $this->db->table('users');
        $query->join('link l','users.id = l.user_id');
        $query->where('l.id',$linkId);

        return $query->get()->getRowArray();
    }


    public function findAllUsers(){
        $query = $this->table('users')->findAll();
        // $query->join('link l','users.id = l.user_id');
        // $query->where('users.status',1);
        // $query->orderBy('l.id','DESC');

        $data = $query;
        d($data);

        return $data;
    }

    public function deleteUser($id){
        $query = $this->db->table('users');
        $query->where('id',$id);
        $query->delete();

    }

    public function disableUser($id){
        $query = $this->db->table('users');
        $query->where('id',$id);
        $query->update(['active' => 0]);
    }

    public function inGroup($group, $idUser){
        
        $query = $this->db->table('auth_groups_users agu');
        $query->join('users u','u.id = agu.user_id');
        $query->join('auth_groups ag','ag.id = agu.group_id');
        $query->where('ag.id',$group);
        $query->where('u.id',$idUser);


        if( $query->countAllResults() != 0){
            return true;
        }else{
            return false;
        }
    }

    public function newUser($data){
        $query = $this->db->table('users');
        $query->insert($data);
        $user = $this->db->insertID(); 
        return $user;
    }

    public function updateUser($data,$id){
        $query = $this->db->table('users');
        $query->where('id',$id);
        $query->update($data);
        $user = $this->db->insertID(); 
        return $user;
    }

    public function findUser($id){
        $query = $this->db->table('users');
        $query->where('id',$id);
        $user = $query->get()->getRowArray();
        return $user;
    }

    
}
