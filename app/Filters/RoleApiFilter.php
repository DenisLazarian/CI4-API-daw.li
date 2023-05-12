<?php

namespace App\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Myth\Auth\Exceptions\PermissionException;
use Myth\Auth\Filters\BaseFilter;

class RoleApiFilter extends BaseFilter implements FilterInterface
{
    /**
     * @param array|null $arguments
     *
     * @return RedirectResponse|void
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        // If no user is logged in then send them to the login form.

        $model = new \App\Models\TokensModel();

        // dd("Hola desde el filtro de roles.");
        $cfgAPI = new \Config\APIJwt();

        $header = $request->header("Authorization");
        // $header = $request->headers();

        $token = null;

        // dd($header);

        // extract the token from the header
        if (!empty($header)) {
            if (preg_match('/Bearer\s(\S+)/', $header, $matches)) {
                $token = $matches[1];
            }
        }



        if (is_null($token) || empty($token)) {
            $response = service('response');
            $response->setBody('Access denied. Token required');
            $response->setStatusCode(401);
            return $response;
        }

        $token_data = JWT::decode($token, new Key($cfgAPI->config()->tokenSecret, $cfgAPI->config()->hash));


        $userModel = model(UserModel::class);
        
        if (empty($arguments)) {
            return;
        }

        // Check each requested permission
        foreach ($arguments as $group) {

            $groupModel = model(GroupModel::class);

            $getRole = $groupModel->where('name', $group)->first();

            if ($userModel->inGroup($getRole->id, $token_data->uid)) {
                return;
            }
        }

        $response = service('response');
        $response->setBody('SMS Filtro: No tienes permiso para realizar esta accion!!');
        $response->setStatusCode(401);
        return $response;

        // return redirect()->to('/')->with('error', lang('Auth.notEnoughPrivilege'));
        // dd("SMS Filtro: No tienes permiso para realizar esta accion!!. ");

        // throw new PermissionException(lang('Auth.notEnoughPrivilege'));
    }

    /**
     * Allows After filters to inspect and modify the response
     * object as needed. This method does not allow any way
     * to stop execution of other after filters, short of
     * throwing an Exception or Error.
     *
     * @param array|null $arguments
     *
     * @return void
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
    }
}
