<?php

namespace App\Models;

use CodeIgniter\Model;
use Myth\Auth\Entities\Group;

class GroupsModel extends Model
{
    protected $DBGroup          = 'default';
    protected $table            = 'auth_groups';
    protected $primaryKey       = 'id';
    protected $useAutoIncrement = true;
    protected $insertID         = 0;
    protected $returnType       = 'array';
    protected $useSoftDeletes   = false;
    protected $protectFields    = true;
    protected $allowedFields    = ['auth_groups'];

    // Dates
    protected $useTimestamps = false;
    protected $dateFormat    = 'datetime';
    protected $createdField  = 'created_at';
    protected $updatedField  = 'updated_at';
    protected $deletedField  = 'deleted_at';

    // Validation
    protected $validationRules      = [];
    protected $validationMessages   = [];
    protected $skipValidation       = false;
    protected $cleanValidationRules = true;

    // Callbacks
    protected $allowCallbacks = true;
    protected $beforeInsert   = [];
    protected $afterInsert    = [];
    protected $beforeUpdate   = [];
    protected $afterUpdate    = [];
    protected $beforeFind     = [];
    protected $afterFind      = [];
    protected $beforeDelete   = [];
    protected $afterDelete    = [];

    public function findAllGroups(){
        $data = $this->table('auth_groups')->findAll();
        return $data;
    }





    public function addUserToGroup(int $userId, int $groupId)
    {
        cache()->delete("{$groupId}_users");
        cache()->delete("{$userId}_groups");
        cache()->delete("{$userId}_permissions");

        $data = [
            'user_id'  => $userId,
            'group_id' => $groupId,
        ];

        return (bool) $this->db->table('auth_groups_users')->insert($data);
    }

    /**
     * Removes a single user from a single group.
     *
     * @param int|string $groupId
     *
     * @return bool
     */
    public function removeUserFromGroup(int $userId, $groupId)
    {
        cache()->delete("{$groupId}_users");
        cache()->delete("{$userId}_groups");
        cache()->delete("{$userId}_permissions");

        return $this->db->table('auth_groups_users')
            ->where([
                'user_id'  => $userId,
                'group_id' => (int) $groupId,
            ])->delete();
    }

    /**
     * Removes a single user from all groups.
     *
     * @return bool
     */
    public function removeUserFromAllGroups(int $userId)
    {
        cache()->delete("{$userId}_groups");
        cache()->delete("{$userId}_permissions");

        return $this->db->table('auth_groups_users')
            ->where('user_id', $userId)
            ->delete();
    }

    /**
     * Returns an array of all groups that a user is a member of.
     *
     * @return array[]
     */
    public function getGroupsForUser(int $userId)
    {
        if (null === $found = cache("{$userId}_groups")) {
            $found = $this->builder()
                ->select('auth_groups_users.*, auth_groups.name, auth_groups.description')
                ->join('auth_groups_users', 'auth_groups_users.group_id = auth_groups.id', 'left')
                ->where('user_id', $userId)
                ->get()->getResultArray();

            cache()->save("{$userId}_groups", $found, 300);
        }

        return $found;
    }

    /**
     * Returns an array of all users that are members of a group.
     *
     * @return array[]
     */
    public function getUsersForGroup(int $groupId)
    {
        if (null === $found = cache("{$groupId}_users")) {
            $found = $this->builder()
                ->select('auth_groups_users.*, users.*')
                ->join('auth_groups_users', 'auth_groups_users.group_id = auth_groups.id', 'left')
                ->join('users', 'auth_groups_users.user_id = users.id', 'left')
                ->where('auth_groups.id', $groupId)
                ->get()->getResultArray();

            cache()->save("{$groupId}_users", $found, 300);
        }

        return $found;
    }

    
   

    

}
