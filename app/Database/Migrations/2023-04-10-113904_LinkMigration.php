<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class LinkMigration extends Migration
{
    public function up()
    {
            $this->forge->addField([
                    'id'          => [
                            'type'           => 'INT',
                            'constraint'     => 11,
                            'auto_increment' => true,
                    ],
                    'name'          => [
                            'type'           => 'VARCHAR',
                            'constraint'     => '255',
                            'null'           => true,
                            'unique'         => 'true',
                    ],
                    'description'          => [
                            'type'           => 'TEXT',
                            'null'           => true,
                    ],
                    'user_id'          => [
                            'type'           => 'INT',
                            'constraint'     => 11,
                            'unsigned'       => true,
                            'null'       => true
                    ],
                    'short_link'          => [
                            'type'           => 'VARCHAR',
                            'constraint'     => '255',
                            'null'           => false,
                            'unique'         => 'true',
                    ],
                    'full_link'          => [
                            'type'           => 'TEXT',
                            'null'           => false,
                            'unique'         => 'true',
                    ],
                    'expiration_date'          => [
                        'type'           => 'DATE',
                        'null'           => true
                    ],
                    'created_date'          => [
                            'type'           => 'DATETIME',
                            'null'           => false,
                    ],
            ]);
            $this->forge->addPrimaryKey('id');
            // $this->db->addKey('name');
    
            // $this->db->addKey('short_link');
    
            // $this->db->addKey('full_link');
    
            $this->forge->addForeignKey('user_id', 'users', 'id', 'CASCADE', 'CASCADE');
            
            $this->forge->createTable('link');
    
    }
    
    public function down()
    {
            $this->forge->dropTable('link');
    }
}
