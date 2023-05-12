<?php

namespace App\Models;

use CodeIgniter\Model;

class LinkModel extends Model
{
    protected $DBGroup          = 'default';
    protected $table            = 'link';
    protected $primaryKey       = 'id';
    protected $useAutoIncrement = true;
    protected $insertID         = 0;
    protected $returnType       = 'array';
    protected $useSoftDeletes   = false;
    protected $protectFields    = true;
    protected $allowedFields    = ['link',"clicks"];

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

    public function findAllLinks(){
        $data = $this->table('link')->findAll();
        return $data;
    }

    public function addLink($data){
        $data = $this->db->table('link')->insert($data);
        $data = $this->db->insertID();

        return $data;
    }

    public function findLink($id){
        $data = $this->table('link')->where('id', $id)->get()->getRowArray();
        return $data;
    }

    public function findLinkByShortLink($sl){
        $data = $this->table('link')->like('short_link', $sl)->get()->getRowArray();
        // dd($data);
        return $data;
    }

    public function updateLink($id, $data){
        $linkUpdated = $this->db->table('link');
        $linkUpdated->where('id',$id) ->update($data);
        
        // $linkUpdated = $this->db->insertID();

        return $id;
    }

    public function deleteById($id) 
    {
        $this->db->table('link')->delete(['id' => $id]);
    }

    public function getClicksByLinkAndDateRange($link, $dateFrom, $dateTo){
        $data = $this->db->table('clicks')
        ->select('link_id,  COUNT(*) as clicks')
        ->join('link', 'link.id = clicks.link_id')
        ->where('link.id',$link)
        ->where('date >=', $dateFrom)
        ->where('date <=', $dateTo)
        ->groupBy('link_id')
        ->get()
        ->getResultArray();

        // d($data);
        return $data;
    }

    public function addClick($data){
        // dd('dato guardado');
        d($data);
        $this->db->table('clicks')->insert($data);
            // dd('guardado');
        
    }
    public function findAllLinksByUser($id){
        $data = $this->table('link')->where('user_id', $id)->findAll();
        return $data;
    }

    public function findLinkByUserAndID($id, $linkId){
        $data = $this->table('link')->where('user_id', $id)->where('id', $linkId)->get()->getRowArray();
        // dd($data);
        return $data;
    }


    public function getRandomShortLink($id){
        $data = $this->table('link')->select("short_link")->where('id', $id)->get()->getRowArray();
        return $data;
    }

    public function getRandomTitle($linkShort){
        if($linkShort == "")
            $linkShort = null;

        if(!$linkShort){
            $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $randomString = substr(str_shuffle($characters), 0, 7);

            $getAllLinks = $this->findAllLinks();

            for ($i=0; $i < count($getAllLinks); $i++) { 
                $linkStringDb = explode('/', $getAllLinks[$i]['short_link'])[4];

                if($linkStringDb == $randomString){
                    $randomString = $this->getRandomTitle($linkShort);
                }else{
                    return $randomString;
                }

            }

            return $randomString;
        }

        return $linkShort;

    }
}
