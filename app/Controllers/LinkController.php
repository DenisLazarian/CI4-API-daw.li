<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use App\Models\ClickModel;
use App\Models\LinkModel;
use App\Models\UserModel;
use Myth\Auth\Config\Auth as AuthConfig;
use Myth\Auth\Entities\User;

class LinkController extends BaseController
{
    public function index()
    {
        session()->start();
        $linkModel =  new LinkModel();
        $userModel = new UserModel();

        // d($userModel->inGroup('admin', session('user')->id));
        // comporvar el grupo al que pertenece el usuario, o si los grupos que tiene, incluie el grupo comprovado
        if($userModel->inGroup('1', session('user')->id))
            $links = $linkModel->findAllLinks();
        else
            $links = $linkModel->findAllLinksByUser(session('user')->id);
        
            // d(session()->getFlashdata('error'));
        
        $error = session()->getFlashdata('error')?? null;
        if($error ?? false) session()->setFlashdata('error', $error);
        
        // d($error);

        $data = [
            'links' => $links,
            'controller' => 'privateSpace'
        ];

        return view('links/list', $data);
    }

    

    public function check(){

        session()->start();
        $error = session()->getFlashdata('error')?? null;

        if(session('isLoggedIn') ?? false){
            return redirect()->to('link/')->with('error', $error);
        }else{
            return redirect()->to('/public')->with('error', $error);
        }
        
    }

    public function publicSite(){
        
        $link = session()->getFlashdata('dataLinks') ?? null;
        // d($link);
        $data=[
            'title'=>"Public Site",
            'controller'=>"public",
            'link' => $link
        ];
        return view('links/public',$data);
    }

    public function createLink(){
        // session()->start();
        helper("form");

        // set Captcha
        $config = [
            "textColor"=>'#fff',
            "backColor"=>'#FF1C1C',
            // "noiceColor"=>'#162453',
            "imgWidth"=>431,
            "imgHeight"=>82,
            "fontSize"=>3,
            // "noiceLines"=>40,
            // "noiceDots"=>20,
            "length" =>6,
            // "text"=> strtoupper(substr($this->auth->user()->username ?? $this->auth->user()->email, 0, 1)),
            "expiration"=>6*MINUTE
        ];
        

        $timage = new \App\Libraries\Text2Image($config);

        $timage->captcha()->html();

        $timage->toJSON();

        $captcha = json_decode($timage->toJSON());
        // d($captcha->text);

        // end Captcha


        $data = [
            'title'=>"Create Link",
            "controller"=>"createLinkForm",
            'captcha' => '<img class=" mt-4 mb-5 w-100" src="data:image/png;base64,' . $timage->toImg64() . '" />',
        ];
        // if($this->request->getPost('destination') == "" ){
        //     return redirect()->back()->withInput();
        // }

        session()->setFlashdata('captchaTx', $captcha->text);

        return view('links/create', $data);
    }

    public function attemptsCreateLink(){

        session()->start();

        
        $txCaptcha = $this->request->getPost('captcha-link') ;
        
        // dd($txCaptcha);
        // dd(session()->getFlashdata('captchaTx'));

        if($txCaptcha != session()->getFlashdata('captchaTx')){
            return redirect()->to('/link/create')->with('errorC', 'The captcha not match'); 
        }

        $linkModel =  new LinkModel();

        $link = $this->request->getPost('destination');
        $linkShort = $this->request->getPost('short-url');
        $linkFile = $this->request->getPost('associate-file');

        if($linkFile){
            $link = base_url('fileget/'.session('user')->username.'/'.$link);
        }
        
        if(session('isLoggedIn') ?? false){
            $title = $this->request->getPost('title');
            $description = $this->request->getPost('description');
            
            // dd($description);

            if($title == "")
                $title = null;
            
            if($description == "")
                $description = null;
    
            $expirationDate = $this->request->getPost('expiration-date');
    
            if($expirationDate == "")
                $expirationDate = null;

        }else{
            $title = null;
            $description = null;
            $expirationDate = null;
            $linkShort = null;
        }

        if(!$linkShort){
            $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $randomString = substr(str_shuffle($characters), 0, 7);
            
            $linkShort = $randomString;
        }

        
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
            
            if($errors['destination'] ) session()->setFlashdata('destError', $errors['destination']);
            
            return redirect()->back()->withInput();
        }
        // dd($expirationDate);
        $link = $linkModel->addLink([
            'full_link' => $link,
            'short_link' => $sLink,
            'user_id' => session('user')->id ?? null,
            'name' => $title,
            'description' => $description,
            'created_date' => date('Y-m-d H:i:s'),
            // 'updated_at' => date('Y-m-d H:i:s'),
            'expiration_date' => $expirationDate,
            'is_file'   =>  ($linkFile ?? false)?true:false
        ]);
        if(session()->get('isLoggedIn') ?? false){
            return redirect()->to('link/');
        }

        session()->setFlashdata('linkNoSessionGenerated', 'Link created successfully! <br><br> <a href="'.$sLink.'">'.$sLink.'</a>');
        
        $data=[
            'title'=>"Public Site",
            'controller'=>"public",
            'link'=>$link ? base_url("daw.li/".$linkShort): "Error",
            'url_link' => base_url("daw.li/".$linkShort),
        ];


        session()->setFlashdata('dataLinks', $data);

        // dd($link);



        
        // return redirect()->to('/');
        return view('links/public',$data);
    }

    public function showLink($id){
            
        session()->start();

        $linkModel =  new LinkModel();
        $link = $linkModel->findLink($id);

        $userModel = new \App\Models\UserModel();
        $userLink = $userModel->getUserLink($link['id']);

        $data = [
            'link' => $link,
            'controller' => 'ajaxRequest',
            'disabled' => ($link['expiration_date'] && ($link['expiration_date'] < date('Y-m-d'))) ,
            'date_created' => date('F j, Y g:i A \G\M\TO',strtotime($link['created_date']) ),
            'user' => $userLink,
        ];
        // dd(date('F j, Y g:i A \G\M\TO',strtotime($link['created_date']) ));

        return view('links/show', $data);
    }

    public function attemptsUpdateLink($id){
        session()->start();

        $linkModel =  new LinkModel();

        $link = $this->request->getPost('destination');
        $linkShort = $this->request->getPost('short-url');

        if(!$linkShort){
            $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $randomString = substr(str_shuffle($characters), 0, 7);
            
            $linkShort = $randomString;
        }
        // d($linkShort);

        $title = $this->request->getPost('title');
        $description = $this->request->getPost('description');

        if($title == "")
            $title = null;
        
        if($description == "")
            $description = null;

        $expirationDate = $this->request->getPost('expiration-date');

        if($expirationDate == "")
            $expirationDate = null;
    

        // dd($expirationDate);
        $linkModel->updateLink($id, [
            'full_link' => $link,
            'short_link' => base_url("daw.li/".$linkShort),
            'user_id' => session('user')->id,
            'name' => $title,
            'description' => $description,
            'created_date' => date('Y-m-d H:i:s'),
            // 'updated_at' => date('Y-m-d H:i:s'),
            'expiration_date' => $expirationDate,
        ]);

        return redirect()->to('/');
    }

    public function deleteLink($id){
        session()->start();

        $linkModel =  new LinkModel();
        $linkModel->deleteById($id);

        return redirect()->to('/');
    }

    public function editLink($id){
        session()->start();

        $linkModel =  new LinkModel();
        $link = $linkModel->findLink($id);

        $data = [
            'title'=>"Edit Link",
            "controller"=>"editLinkForm",
            'link' => $link,
        ];
        // d($link);
        
        return view('links/edit', $data);
    }

    public function attempLink($shortLink){ // daw.li/linkName

        $linkModel =  new LinkModel();
        $clickModel = new ClickModel();
        $link = $linkModel->findLinkByShortLink($shortLink);

        if(($link['description'] ?? false) && !$this->request->getGet("showed")){
            
            echo view('links/_description', ['link' => $link]);
        }else{
            if($link){
                if($link['expiration_date'] && ($link['expiration_date'] < date('Y-m-d'))){ // link invalido
                    return redirect()->to('/') -> with('error',"invalid link or expired");
                }
                $data=[
                    'link_id' => $link['id'],
                    'date' => date('Y-m-d'),
                ];
    
                $clickModel->addClick($data);
    
                return redirect()->to($link['full_link']);
            }
            return redirect()->to('/')->with('error',"invalid link or expired");

        }

    }

    // public function showDescription(){

        

    // }

    public function getResult(){

        session()->start();

        
        if($this->request->getGet('controller') != "ajaxResultClicks"){
            return redirect()->to('/');
        }

        $linkModel =  new LinkModel();

        $link = $this->request->getGet('linkId');
        $dateFrom = $this->request->getGet('dateIni');
        $dateTo = $this->request->getGet('dateFinal');

        $clicksValues = $linkModel->getClicksByLinkAndDateRange($link, $dateFrom, $dateTo);
        // d($clicksValues);
        $clicksValues = $clicksValues[0]??[0];
        
        return view('links/_result', $clicksValues);

    }
    
}
