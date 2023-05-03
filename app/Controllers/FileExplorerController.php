<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use App\Models\UserModel;
use elFinder;
use elFinderConnector;

class FileExplorerController extends BaseController
{
     /**
     *
     * @method public getFile
     *
     * @link
     * @version 1.0 20220214
     * @author JMFXR
     *
     */
    public function getFile()
    {
        session()->start();
        $varName=current_url(true)->setSegment(1,'')->getPath();
        d(WRITEPATH);
        $fichero = str_replace("/fileget/","", WRITEPATH.'uploads\\' . ($varName));
        d($fichero);
        // dd($varName);

        $userModel = new UserModel();

        if($userModel->inGroup('admin', session('user')->id) ||$userModel->inGroup('user', session('user')->id) ){
            // dd(file_exists($fichero));
            if($userModel->inGroup('user', session('user')->id)){
                $fileUser = explode('/',$varName);

                if($fileUser != session('user') ->username){
                    return redirect()->to('/')->with('error', 'You have no autorization to see this file');
                }
            }

            if (file_exists($fichero)) {
                header('Content-Description: File Transfer');
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="'.basename($fichero).'"');
                header('Expires: 0');
                header('Cache-Control: must-revalidate');
                header('Pragma: public');
                header('Content-Length: ' . filesize($fichero));
                readfile($fichero);
                redirect()->to('/');
            }
            
        }

        return redirect()->to('/')->with('error', 'There is a problem with the file');



        // dd('no ha funcionado');
        // return redirect()->to(str_replace('/fileget/',base_url(),$varName));
    }

    public function manager()
    {
        session()->start();
        $data['page_title'] = 'File explorer';
        $data['title'] = 'File explorer';
        $data['connector'] = base_url('/fileconnector');
        $data['controller'] = "news_boot_css";

        echo view('explorer/manager', $data);
    }

    public function connector()
    {
        // session()->start();

        $path = WRITEPATH . '/uploads';

        $modelUser = new UserModel();

        if($modelUser-> inGroup('admin',session('user')->id)){
            $path = WRITEPATH . '/uploads';
        }elseif($modelUser-> inGroup('user',session('user')->id)){
            $path=WRITEPATH . '/uploads/'.session('user')->username.'/.';
        }

        // dd($path);

        $opts = array(
            'debug' => true,
            'roots' => array(
                array(
                    'driver'        => 'LocalFileSystem',
                    'path'          => $path,
                    'URL'           => base_url('fileget'),
                    // 'uploadDeny'    => array('all'),                  // All Mimetypes not allowed to upload
                    // 'uploadAllow'   => array('image', 'text/plain', 'application/pdf'), // Mimetype `image` and `text/plain` allowed to upload
                    // 'uploadOrder'   => array('deny', 'allow'),        // allowed Mimetype `image` and `text/plain` only
                    'accessControl' => array($this, 'elfinderAccess'), // disable and hide dot starting files (OPTIONAL)
                    'alias'         => 'Documents',
                    'attributes' => array(
                        array(
                            'pattern' => '/\.zop$/', //You can also set permissions for file types by adding, for example, .jpg inside pattern.
                            'read'    => false,
                            'write'   => false,
                            'locked'  => true,
                            'hidden'  => true
                        ),
                        array(
                            'pattern' => '/personal.* /', //comença per la paraula pesonal (expressio regular entre barres)
                            'read'    => false,
                            'write'   => false,
                            'locked'  => true,
                            'hidden'  => false
                        )
                    ),
                    // more elFinder options here
                )
            ),
        );
        $connector = new elFinderConnector(new elFinder($opts));
        $connector->run();
    }

    public function elfinderAccess($attr, $path, $data, $volume, $isDir, $relpath)
    {

        /*function startsWith($haystack, $needle) {
            return substr_compare($haystack, $needle, 0, strlen($needle)) === 0;
        }
        function endsWith($haystack, $needle) {
            return substr_compare($haystack, $needle, -strlen($needle)) === 0;
        }*/


        $basename = basename($path);

        if (substr_compare($basename, '.html', -5) === 0)
            return !($attr == 'read' || $attr == 'write');
        else {

            return $basename[0] === '.'                  // if file/folder begins with '.' (dot)
                && strlen($relpath) !== 1           // but with out volume root
                ? !($attr == 'read' || $attr == 'write') // set read+write to false, other (locked+hidden) set to true
                :  null;                                 // else elFinder decide it itself

        }
    }
}



// en la funcion fileGet


        // $file = new \CodeIgniter\Files\File(WRITEPATH . "/uploads/" . urldecode($varName));

        // // dd(str_replace('/fileget/',base_url(),$varName));
        // d($file->isFile());
        // if (!$file->isFile()){     // if (!is_file(WRITEPATH . "/uploads/" . $varName)){
        //     throw new \CodeIgniter\Exceptions\PageNotFoundException($varName . ' no found');
        // }

        // $filedata = readfile(WRITEPATH . "/uploads/" . $varName);
        // $filedata = new \SplFileObject($file->getPathname(), "r");

        // $data1 = $filedata->fread($filedata->getSize());

        // return $this->response->setContentType($file->getMimeType())->setBody($data1);