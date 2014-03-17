/*
if (window.rcmail) {
    rcmail.addEventListener("init", function() {
        this.password = "";

        if (rcmail.env.action === "compose") {
            // Clear password if identity changed
            rcmail.addEventListener("change_identity", function() {
                this.passphrase = "";
            });
            rcmail.addEventListener("beforesend", function(e) {
                if(!beforeSend()) {
                    return false;
                }
            });
        }
    });

    function beforeSend() {
        if (!$("#smime_encrypt").is(":checked") && !$("#smime_sign").is(":checked")) {
            if (confirm(rcmail.gettext("smime_continue_unencrypted", "rc_smime"))) {
                // remove the public key attachment since we don't sign nor encrypt the message
                // removePublicKeyAttachment();
                return true;
            } else {
                return false;
            }
        }

        // Sign only
        if ($("#smime_sign").is(":checked") && !$("#smime_encrypt").is(":checked")) {
            if (confirm(rcmail.gettext("smime_get_password", "rc_smime"))) {
                return true;
            } else {
                return false;
            }
        }
    }
}
*/