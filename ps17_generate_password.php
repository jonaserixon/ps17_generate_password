<?php

include_once('./config/config.inc.php');
include_once('./init.php');

class ErixonResetPW
{
    /** @var array should contain hashing methods */
    private $hashMethods = array();

    /**
     * Check if it's the first function of the array that was used for hashing.
     *
     * @param string $passwd The password you want to check
     * @param string $hash The hash you want to check
     * @param string $staticSalt A static salt
     *
     * @return bool Result of the verify function
     */
    public function isFirstHash($passwd, $hash, $staticSalt = _COOKIE_KEY_)
    {
        if (!count($this->hashMethods)) {
            $this->initHashMethods();
        }

        $closure = reset($this->hashMethods);

        return $closure['verify']($passwd, $hash, $staticSalt);
    }

    /**
     * Iterate on hash_methods array and return true if it matches.
     *
     * @param string $passwd The password you want to check
     * @param string $hash The hash you want to check
     * @param string $staticSalt A static salt
     *
     * @return bool `true` is returned if the function find a match else false
     */
    public function checkHash($passwd, $hash, $staticSalt = _COOKIE_KEY_)
    {
        if (!count($this->hashMethods)) {
            $this->initHashMethods();
        }

        foreach ($this->hashMethods as $closure) {
            if ($closure['verify']($passwd, $hash, $staticSalt)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Hash the `$plaintextPassword` string and return the result of the 1st hashing method
     * contained in PrestaShop\PrestaShop\Core\Crypto\Hashing::hash_methods.
     *
     * @param string $plaintextPassword The password you want to hash
     * @param string $staticSalt The static salt
     *
     * @return string
     */
    public function hash($plaintextPassword, $staticSalt = _COOKIE_KEY_)
    {
        if (!count($this->hashMethods)) {
            $this->initHashMethods();
        }

        $closure = reset($this->hashMethods);

        return $closure['hash']($plaintextPassword, $staticSalt, $closure['option']);
    }

    /**
     * Init $hash_methods.
     */
    private function initHashMethods()
    {
        $this->hashMethods = array(
            'bcrypt' => array(
                'option' => array(),
                'hash' => function ($passwd, $staticSalt, $option) {
                    return password_hash($passwd, PASSWORD_BCRYPT);
                },
                'verify' => function ($passwd, $hash, $staticSalt) {
                    return password_verify($passwd, $hash);
                },
            ),
            'md5' => array(
                'option' => array(),
                'hash' => function ($passwd, $staticSalt, $option) {
                    return md5($staticSalt . $passwd);
                },
                'verify' => function ($passwd, $hash, $staticSalt) {
                    return md5($staticSalt . $passwd) === $hash;
                },
            ),
        );
    }
}

$url = '//'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];

$html = '<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); -ms-transform: translate(-50%, -50%); -webkit-transform: translate(-50%, -50%);">
            <form name="generate_hash" action="'.$url.'" style="padding: 10px; border: 1px solid lightgrey;">
                <input id="new_password" name="new_password" value="'.Tools::getValue('new_password').'" placeholder="Enter new password"/>
                <label>Enter a new password</label>
                </br></br>
                <input id="cookie_key" name="cookie_key" value="'.Tools::getValue('cookie_key').'" placeholder="Enter cookie_key"/>
                <label>Enter cookie_key found in <strong>/app/config/parameters.php</strong></label>
                </br></br>
                <button type="submit" id="generate_button">Generate hash</button>
                <button id="reset_button" type="button">Reset</button>
            </form>
            </br></br>
            Update <strong>ps_employee.passwd</strong> field with the generated hash and login with your new password
        </div>';

$javascript = '<script>
                let reset_button = document.querySelector("#reset_button");
                reset_button.addEventListener("click", function() {
                    window.location.href =  window.location.href.split("?")[0];
                });
            </script>';

echo $html . $javascript;

if (Tools::getIsset('new_password') && strlen(Tools::getValue('new_password')) > 0 && Tools::getIsset('cookie_key') && strlen(Tools::getValue('cookie_key')) > 0) {
    $reset_pw = new ErixonResetPW();
    $cookie_key = Tools::getIsset('cookie_key');
    $new_password = $reset_pw->hash(Tools::getValue('new_password'), $cookie_key);

    $javascript = '<script>
        confirm("'.$new_password.'");
    </script>';

    echo $javascript;

} else {
    echo 'Missing parameter: ';
    if (!Tools::getIsset('new_password')) {
        echo '<pre>new_password</pre>';
    }

    if (!Tools::getIsset('cookie_key')) {
        echo '<pre>cookie_key</pre>';
    }
}
