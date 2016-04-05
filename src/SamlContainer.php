<?php
namespace Sil\IdpPw\Auth;

use SAML2\Compat\AbstractContainer;
use yii\helpers\Url;

class SamlContainer extends AbstractContainer
{
    public function getLogger()
    {
        return \Yii::getLogger();
    }

    public function generateId()
    {
        return microtime();
    }

    public function debugMessage($message, $type)
    {

    }

    public function redirect($url, $data = [])
    {
        $url = Url::to([$url, $data], true);
        header('Location: ' . $url);
    }

    public function postRedirect($url, $data = [])
    {
        $this->redirect($url, $data);
    }
}
