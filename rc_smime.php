<?php

class rc_smime extends rcube_plugin
{
    public $task = 'mail|settings';

    private $rc;
    private $uname = '';
    private $homedir;
    private $css_loaded;
    private $dir_checked;
    private $signatures   = array();
    private $signed_parts = array();

    function init()
    {
        $this->rc    = rcube::get_instance();
        $this->uname = $this->rc->user->get_username();
        $homedir     = $this->rc->config->get('rc_smime_homedir', $this->home . '/users');

        if (!$this->dir_checked) {
            $this->check_dir($homedir);
            $this->dir_checked = true;
        }

        if ($this->rc->task == 'mail') {
            // include localization (if wasn't included before)
            $this->add_texts('localization/', true);
            $this->load_css();
            // load javascript
            $this->include_script('rc_smime.js');

            // message parse/display hooks
            $this->add_hook('message_body_prefix', array($this, 'message_body_prefix_hook'));
            $this->add_hook('message_part_structure', array($this, 'message_part_structure_hook'));
        } elseif ($this->rc->task == 'settings') {
        }
    }

    function message_body_prefix_hook($args)
    {
        $part_id = $args['part']->mime_id;

        // skip: not a message part
        if ($args['part'] instanceof rcube_message) {
            return $args;
        }

        // Signature verification status
        if (isset($this->signed_parts[$part_id]) && ($sig = $this->signatures[$this->signed_parts[$part_id]])) {
            $attrib['id'] = 'smime-message';
            $smime_sender = '';
            if (is_array($sig['email'])) {
                foreach ($sig['email'] as $email) {
                    if ($smime_sender != '') {
                        $smime_sender .= ' ' . $this->gettext('alias') . ' ';
                    }

                    $smime_sender .= ($sig['name'] ? $sig['name'] . ' ' : '') . '<' . $email . '>';
                }
            } else {
                $smime_sender = ($sig['name'] ? $sig['name'] . ' ' : '') . '<' . $sig['email'] . '>';
            }

            switch ($sig['valid']) {
                case "valid":
                    $attrib['class'] = 'smime-notice';
                    $smime_msg       = rcube::Q($this->gettext(array(
                        'name' => 'sigvalid',
                        'vars' => array(
                            'sender' => $smime_sender,
                            'issuer' => $sig['issuer'],
                        ),
                    )));
                    break;
                case "unverified":
                    $attrib['class'] = 'smime-warning';
                    $smime_msg       = rcube::Q($this->gettext(array(
                        'name' => 'sigunverified',
                        'vars' => array(
                            'sender' => $smime_sender,
                            'issuer' => $sig['issuer'],
                        ),
                    )));
                    break;
                default:
                    $attrib['class'] = 'smime-error';
                    $smime_msg       = rcube::Q($this->gettext('siginvalid'));
            }

            $args['prefix'] .= html::div($attrib, $smime_msg);

            // Display each signature message only once
            unset($this->signatures[$this->signed_parts[$part_id]]);
        }

        return $args;
    }

    function message_part_structure_hook($args)
    {
        if ($args['mimetype'] == 'multipart/signed') {
            $this->parse_signed($args);
        }

        return $args;
    }

    private function parse_signed(&$args)
    {
        $struct = $args['structure'];

        // S/MIME
        if ($first_part = $struct->parts[1]) {
            $mime_type = $first_part->mimetype;
            if ($mime_type == 'application/pkcs7-signature' || $mime_type == 'application/x-pkcs7-signature') {
                $this->parse_smime_signed($args);
            }
        }
    }

    private function parse_smime_signed(&$args)
    {
        $struct = $args['structure'];
        $msg    = $args['object'];

        // Verify signature
        if ($this->rc->action == 'show' || $this->rc->action == 'preview') {
            $msg_part  = $struct->parts[0];
            $full_file = tempnam($this->homedir, 'rcube_mail_full_');
            $cert_file = tempnam($this->homedir, 'rcube_mail_cert_');
            $part_file = tempnam($this->homedir, 'rcube_mail_part_');

            $full_handle = fopen($full_file, "w");
            $fullbody    = $this->rc->storage->get_raw_body($msg->uid, $full_handle);
            fclose($full_handle);

            $out = array(
                'error' => array(),
            );
            $sig = openssl_pkcs7_verify($full_file, 0, $cert_file);

            $errorstr = $this->get_openssl_error();
            if (strlen($errorstr) > 0) {
                $out['error']['verify1'] = $errorstr;
            }

            if ($sig === true) {
                $out = $this->get_user_info_from_cert($cert_file, 'valid');
            } else {
                $sig      = openssl_pkcs7_verify($full_file, PKCS7_NOVERIFY, $cert_file);
                $errorstr = $this->get_openssl_error();
                if (strlen($errorstr) > 0) {
                    $out['error']['verify2'] = $errorstr;
                }

                if ($sig === true) {
                    $out = $this->get_user_info_from_cert($cert_file, 'unverified');
                } elseif ($sig === false) {
                    $out['valid'] = 'invalid';
                } else {
                    $part_handle = fopen($part_file, "w");
                    $mimes       = $this->rc->storage->conn->fetchMIMEHeaders($msg->folder, $msg->uid, $struct->mime_id, true);
                    foreach (array_values($mimes) as $mime) {
                        fwrite($part_handle, $mime);
                    }

                    fwrite($part_handle, "\n");
                    $part_out = $this->rc->storage->conn->handlePartBody($msg->folder, $msg->uid, true, $struct->mime_id, null, null, $part_handle);
                    fclose($part_handle);
                    $sig      = openssl_pkcs7_verify($part_file, 0, $cert_file);
                    $errorstr = $this->get_openssl_error();
                    if (strlen($errorstr) > 0) {
                        $out['error']['verify3'] = $errorstr;
                    }

                    if ($sig === true) {
                        $out = $this->get_user_info_from_cert($cert_file, 'valid');
                    } else {
                        $sig      = openssl_pkcs7_verify($part_file, PKCS7_NOVERIFY, $cert_file);
                        $errorstr = $this->get_openssl_error();
                        if (strlen($errorstr) > 0) {
                            $out['error']['verify4'] = $errorstr;
                        }

                        if ($sig === true) {
                            $out = $this->get_user_info_from_cert($cert_file, 'unverified');
                        } elseif ($sig === false) {
                            $out['valid'] = 'invalid';
                        } else {
                            $out['valid'] = 'error';
                        }
                    }
                }
            }

            if (count($out['error']) == 0) {
                unset($out['error']);
            }

            unlink($full_file);
            unlink($cert_file);
            unlink($part_file);

            $this->signatures[$struct->mime_id] = $out;
            // Message can be multipart (assign signature to each subpart)
            $this->set_signed_parts($msg_part, $struct->mime_id);
        }

        return $args;
    }

    private function get_user_info_from_cert($file, $valid)
    {
        $cert     = openssl_x509_parse(file_get_contents($file));
        $errorstr = $this->get_openssl_error();
        $sub      = $cert['subject'];
        $ret      = array(
            'error' => $errorstr,
            'valid' => $valid,
        );

        if (array_key_exists('emailAddress', $sub)) {
            $ret['email'] = $sub['emailAddress'];
        }

        if (array_key_exists('CN', $sub)) {
            $ret['name'] = $sub['CN'];
        }

        if (array_key_exists('issuer', $cert)) {
            $issuer = $cert['issuer'];
            if (array_key_exists('O', $issuer)) {
                $ret['issuer'] = $issuer['O'];
            }
        }

        // Scan subAltName for email addresses
        if (array_key_exists('extensions', $cert) && array_key_exists('subjectAltName', $cert['extensions'])) {
            $emailAddresses = array();
            foreach (explode(', ', $cert['extensions']['subjectAltName']) as $altName) {
                $parts = explode(':', $altName);
                if ($parts[0] == 'email') {
                    array_push ($emailAddresses, $parts[1]);
                }
            }

            if (count($emailAddresses) > 0) {
                $ret['email'] = $emailAddresses;
            }
        }

        return $ret;
    }

    private function get_openssl_error()
    {
        $tmp = array();
        while ($errorstr = openssl_error_string()) {
            $tmp[] = $errorstr;
        }

        $ret = join("\n", array_values($tmp));
        return strlen($ret) > 0 ? $ret : null;
    }

    private function set_signed_parts($msg_part, $id)
    {
        if (!empty($msg_part->parts)) {
            foreach ($msg_part->parts as $part) {
                $this->signed_parts[$part->mime_id] = $id;
                if (!empty($part->parts)) {
                    $this->set_signed_parts($part, $id);
                }
            }
        } else {
            $this->signed_parts[$msg_part->mime_id] = $id;
        }
    }

    /**
     * Checks if specified message part contains body data.
     * If body is not set it will be fetched from IMAP server.
     *
     * @param rcube_message_part Message part object
     * @param integer            Message UID
     */
    private function set_part_body($part, $uid)
    {
        if (!isset($part->body)) {
            $part->body = $this->rc->storage->get_message_part($uid, $part->mime_id, $part);
        }
    }

    private function load_css()
    {
        if ($this->css_loaded) {
            return;
        } else {
            $this->include_stylesheet("skins/rc_smime.css");
            $this->css_loaded = true;
        }
    }

    private function check_dir($dir)
    {
        // check if homedir exists (create it if not) and is readable
        if (!$dir) {
            return $this->rc->raise_error(array(
                'code'    => 999,
                'type'    => 'php',
                'file'    => __FILE__,
                'line'    => __LINE__,
                'message' => "Option 'rc_smime_homedir' not specified",
            ), true, false);
        }

        if (!file_exists($dir)) {
            return $this->rc->raise_error(array(
                'code'    => 999,
                'type'    => 'php',
                'file'    => __FILE__,
                'line'    => __LINE__,
                'message' => "Keys directory doesn't exists: $dir",
            ), true, false);
        }

        if (!is_writable($dir)) {
            return $this->rc->raise_error(array(
                'code'    => 999,
                'type'    => 'php',
                'file'    => __FILE__,
                'line'    => __LINE__,
                'message' => "Keys directory isn't writeable: $dir",
            ), true, false);
        }

        $dir = $dir . '/' . $this->uname;

        // check if user's homedir exists (create it if not) and is readable
        if (!file_exists($dir)) {
            mkdir($dir, 0700);
        }

        if (!file_exists($dir)) {
            return $this->rc->raise_error(array(
                'code'    => 999,
                'type'    => 'php',
                'file'    => __FILE__,
                'line'    => __LINE__,
                'message' => "Unable to create keys directory: $dir",
            ), true, false);
        }

        if (!is_writable($dir)) {
            return $this->rc->raise_error(array(
                'code'    => 999,
                'type'    => 'php',
                'file'    => __FILE__,
                'line'    => __LINE__,
                'message' => "Unable to write to keys directory: $dir",
            ), true, false);
        }

        $this->homedir = $dir;
    }
}
