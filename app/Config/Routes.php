<?php

namespace Config;

// Create a new instance of our RouteCollection class.
$routes = Services::routes();

/*
 * --------------------------------------------------------------------
 * Router Setup
 * --------------------------------------------------------------------
 */
$routes->setDefaultNamespace('App\Controllers');
$routes->setDefaultController('LinkController');
$routes->setDefaultMethod('check');
$routes->setTranslateURIDashes(false);
$routes->set404Override();
// The Auto Routing (Legacy) is very dangerous. It is easy to create vulnerable apps
// where controller filters or CSRF protection are bypassed.
// If you don't want to define all routes, please use the Auto Routing (Improved).
// Set `$autoRoutesImproved` to true in `app/Config/Feature.php` and set the following to true.
// $routes->setAutoRoute(false);

/*
 * --------------------------------------------------------------------
 * Route Definitions
 * --------------------------------------------------------------------
 */

// We get a performance increase by specifying the default
// route since we don't have to scan directories.

$routes->get('/', 'LinkController::check');



// Login/out
$routes->get('login', 'AuthController::login');
$routes->post('login', 'AuthController::attemptLogin');
$routes->get('logout', 'AuthController::logout');

// Registration
$routes->get('register', 'AuthController::register');
$routes->post('register', 'AuthController::attemptRegister');

// Activation
$routes->get('activate-account', 'AuthController::activateAccount');
$routes->get('resend-activate-account', 'AuthController::resendActivateAccount');

// Forgot/Resets
$routes->get('forgot', 'AuthController::forgotPassword');
$routes->post('forgot', 'AuthController::attemptForgot');
$routes->get('reset-password', 'AuthController::resetPassword');
$routes->post('reset-password', 'AuthController::attemptReset');


$routes->group('link', function($routes){
    // $routes->get('/', 'AdminController::index');
    // $routes->get('users', 'AdminController::users');
    // $routes->get('links', 'AdminController::links');
    // $routes->get('settings', 'AdminController::settings');
    
    $routes->get('create', 'LinkController::createLink');
    $routes->post('create_post', 'LinkController::attemptsCreateLink');
    
    $routes->group('',['filter' => 'role:admin,user'], function($routes){
        $routes->get('/', 'LinkController::index');
        $routes->get('show/(:segment)', 'LinkController::showLink/$1');
        $routes->get('edit/(:segment)', 'LinkController::editLink/$1');
        $routes->post('update/(:segment)', 'LinkController::attemptsUpdateLink/$1');
        $routes->post('delete/(:segment)', 'LinkController::deleteLink/$1');

        $routes->get('result', 'LinkController::getResult');
    });
    
});


$routes->group('admin',['filter'=> 'role:admin'], function($routes){
    $routes->get('/', 'UserController::list');
    $routes->get('edit/(:segment)', 'UserController::edit/$1');
    $routes->post('update/(:segment)', 'UserController::update/$1');
    $routes->post('delete/(:segment)', 'UserController::delete/$1');
    $routes->get('disabled-account/(:segment)', 'UserController::disable/$1');
    $routes->get('create', 'UserController::create');
    $routes->post('save', 'UserController::save');
});

$routes->get('daw.li/(:segment)',"LinkController::attempLink/$1");

$routes->get('public', 'LinkController::publicSite');

// $routes->get('description', 'linkController::')
// explorer

$routes->group('',['filter'=>'role:admin,user'], function($routes){
    $routes->post('fileconnector', 'FileExplorerController::connector');
    $routes->get('fileconnector', 'FileExplorerController::connector');
    $routes->get('filemanager', 'FileExplorerController::manager');
    $routes->get('fileget/(:any)', 'FileExplorerController::getFile');
});



/*
 * --------------------------------------------------------------------
 * Additional Routing
 * --------------------------------------------------------------------
 *
 * There will often be times that you need additional routing and you
 * need it to be able to override any defaults in this file. Environment
 * based routes is one such time. require() additional route files here
 * to make that happen.
 *
 * You will have access to the $routes object within that file without
 * needing to reload it.
 */
if (is_file(APPPATH . 'Config/' . ENVIRONMENT . '/Routes.php')) {
    require APPPATH . 'Config/' . ENVIRONMENT . '/Routes.php';
}
