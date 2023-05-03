<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class ClicksMigration extends Migration
{
    public function up()
{
        $this->forge->addField([
                'id'          => [
                        'type'           => 'INT',
                        'constraint'     => 11,
                        'auto_increment' => true,
                ],
                'link_id'          => [
                        'type'           => 'INT',
                        'constraint'     => 11,
                ],
                'date'          => [
                        'type'           => 'DATE',
                ],
        ]);
        $this->forge->addKey('id', true);
        $this->forge->addForeignKey('link_id', 'link', 'id', 'CASCADE', 'CASCADE');
        
        $this->forge->createTable('clicks');

}

public function down()
{
        $this->forge->dropTable('clicks');
}
}
