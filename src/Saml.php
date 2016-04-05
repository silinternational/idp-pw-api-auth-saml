<?php
namespace Sil\IdpPw\Auth;

use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Compat\ContainerSingleton;
use SAML2\AuthnRequest;
use SAML2\EncryptedAssertion;
use SAML2\HTTPPost;
use SAML2\HTTPRedirect;
use Sil\IdpPw\Common\Auth\AuthnInterface;
use Sil\IdpPw\Common\Auth\InvalidLoginException;
use Sil\IdpPw\Common\Auth\User as AuthUser;
use yii\base\Component;
use yii\web\Request;

class Saml extends Component implements AuthnInterface
{

    /**
     * Whether or not to sign request
     * @var bool [default=true]
     */
    public $signRequest = true;

    /**
     * Whether or not response should be signed
     * @var bool [default=true]
     */
    public $checkResponseSigning = true;

    /**
     * Whether or not to require response assertion to be encrypted
     * @var bool [default=true]
     */
    public $requireEncryptedAssertion = true;

    /**
     * Certificate contents for remote IdP
     * @var string
     */
    public $idpCertificate;

    /**
     * Certificate contents for this SP
     * @var string|null If null, request will not be signed
     */
    public $spCertificate;

    /**
     * PEM encoded private key file associated with $spCertificate
     * @var string|null If null, request will not be signed
     */
    public $spPrivateKey;

    /**
     * AES-128-CBC encryption key for decrypting attribute data
     * @var string|null If null, response is not expected to be encrypted
     */
    public $encryptionKey;

    /**
     * URL for this SP for user to be returned to after login
     * @var string
     */
    public $assertionConsumerServiceUrl;

    /**
     * This SP Entity ID as known by the remote IdP
     * @var string
     */
    public $entityId;

    /**
     * Single-Sign-On url for remote IdP
     * @var string
     */
    public $ssoUrl;

    /**
     * Single-Log-Out url for remote IdP
     * @var string
     */
    public $sloUrl;

    /**
     * Mapping configuration for IdP attributes to User
     * @var array
     */
    public $attributeMap;

    public function init()
    {
        /*
         * Ensure all required properties are set
         */
        $required = [
            'assertionConsumerServiceUrl', 'ssoUrl', 'sloUrl', 'attributeMap'
        ];
        foreach($required as $field) {
            if(is_null($this->$field)) {
                throw new \Exception(
                    'Missing required configuration for ' . $field . ' in auth component configuration',
                    1459883515
                );
            }
        }

        /*
         * Ensure conditionally required properties are set when needed
         */
        if($this->signRequest && (is_null($this->spCertificate) || is_null($this->spPrivateKey)) ) {
            throw new \Exception(
                'Signing requests requires spCertificate and spPrivateKey to be set in auth component configuration',
                1459883965
            );
        }

        if($this->checkResponseSigning && is_null($this->idpCertificate)) {
            throw new \Exception(
                'Checking if responses are signed requires idpCertificate to be set in auth component configuration',
                145988396
            );
        }

        if($this->requireEncryptedAssertion && is_null($this->encryptionKey)) {
            throw new \Exception(
                'Decrypting assertions requires encryptionKey to be set in auth component configuration',
                145988397
            );
        }

        parent::init();
    }

    /**
     * @param \yii\web\Request|null $request
     * @return \Sil\IdpPw\Common\Auth\User|null If null is returned the user was redirected to IdP
     * @throws \Sil\IdpPw\Common\Auth\InvalidLoginException
     */
    public function login(Request $request = null)
    {
        $container = new SamlContainer();
        ContainerSingleton::setContainer($container);

        $request = new AuthnRequest();
        $request->setId($container->generateId());
        $request->setAssertionConsumerServiceURL($this->assertionConsumerServiceUrl);
        /*
         * Issuer defaults to assertionConsumerServiceUrl, but can be overriden by setting entityId
         */
        if(!is_null($this->entityId)) {
            $request->setIssuer($this->entityId);
        } else {
            $request->setIssuer($this->assertionConsumerServiceUrl);
        }

        $request->setDestination($this->ssoUrl);

        /*
         * Sign request if spCertificate and spPrivateKey are provided
         */
        if($this->signRequest && $this->spCertificate && $this->spPrivateKey) {
            $request->setCertificates($this->spCertificate);

            $key = new XMLSecurityKey(
                XMLSecurityKey::RSA_SHA1,
                ['type' => 'private']
            );
            $key->loadKey($this->spPrivateKey,false);
            $request->setSignatureKey($key);
        }


        try {
            /*
             * Check for SAMLRequest or SAMLResponse to see if user is returning after login
             */
            $binding = new HTTPPost();

            /** @var \SAML2\Response $response */
            $response = $binding->receive();
        } catch (\Exception $e) {
            /*
             * User was not logged in, so redirect to IdP for login
             */
            $binding = new HTTPRedirect();
            $binding->send($request);

            return null;
        }

        try{

            /*
             * If needed, check if response is signed
             */
            if($this->checkResponseSigning) {
                $idpKey = new XMLSecurityKey(
                    XMLSecurityKey::RSA_SHA1,
                    ['type' => 'public']
                );
                $idpKey->loadKey($this->idpCertificate,false,true);
                if(!$response->validate($idpKey)) {
                    throw new \Exception(
                        'SAML response was not signed properly',
                        1459884735
                    );
                }
            }

            /** @var \SAML2\Assertion[]|\SAML2\EncryptedAssertion[] $assertions */
            $assertions = $response->getAssertions();

            /*
             * If requiring encrypted assertion, use key to decrypt it
             */
            if($this->requireEncryptedAssertion) {
                $decryptKey = new XMLSecurityKey(
                    XMLSecurityKey::AES128_CBC,
                    ['type' => 'private']
                );
                $decryptKey->loadKey($this->encryptionKey,false,false);

                if( ! $assertions[0] instanceof EncryptedAssertion) {
                    throw new \Exception(
                        'Response assertion is required to be encrypted but was not',
                        1459884392
                    );
                }

                /** @var \SAML2\Assertion $assertion */
                $assertion = $assertions[0]->getAssertion($decryptKey);
            } else {
                $assertion = $assertions[0];
            }

            /*
             * Get attributes using mapping config, make sure expected fields
             * are present, and return as new User
             */
            $samlAttrs = $assertion->getAttributes();
            $normalizedAttrs = $this->extractSamlAttributes($samlAttrs, $this->attributeMap);
            $this->assertHasRequiredSamlAttributes($normalizedAttrs, $this->attributeMap);

            $authUser = new AuthUser();
            $authUser->firstName = $normalizedAttrs['first_name'];
            $authUser->lastName = $normalizedAttrs['last_name'];
            $authUser->email = $normalizedAttrs['email'];
            $authUser->employeeId = $normalizedAttrs['employee_id'];
            $authUser->idpUsername = $normalizedAttrs['idp_username'];

            return $authUser;

        } catch (\Exception $e) {
            /*
             * An error occurred processing SAML data
             */
            throw new InvalidLoginException($e->getMessage(), 1459803743);
        }

    }

    /**
     * @param \Sil\IdpPw\Common\Auth\User $user
     * @return void|null
     */
    public function logout(AuthUser $user = null)
    {
        header('Location: '.$this->sloUrl);
        return null;
    }

    /**
     * Utility function to extract attribute values from SAML attributes and
     * return as a simple array
     * @param $attributes array the SAML attributes returned
     * @param $map array configuration map of attribute names with field and element values
     * @return array
     */
    public function extractSamlAttributes($attributes, $map)
    {
        $attrs = [];

        foreach($map as $attr => $details){
            if(isset($details['element'])){
                if(isset($attributes[$details['field']][$details['element']])){
                    $attrs[$attr] = $attributes[$details['field']][$details['element']];
                }
            } else {
                if(isset($attributes[$details['field']])){
                    $attrs[$attr] = $attributes[$details['field']];
                }
            }
        }

        return $attrs;
    }

    /**
     * Check if given array of $attributes includes all keys from $map
     * @param array $attributes
     * @param array $map
     * @throws \Exception
     */
    public function assertHasRequiredSamlAttributes($attributes, $map)
    {
        foreach ($map as $key => $value) {
            if(!array_key_exists($key, $attributes)){
                throw new \Exception("SAML attributes missing attribute: $key",1454436522);
            }
        }
    }
}