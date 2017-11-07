/**
 * Created by ICARA on 22-Oct-17.
 */

$(document).ready(function () {
    new Clipboard('#copy_api');
    // new Clipboard('.btn');

    document.getElementById("uploadBtn").onchange = function () {
        document.getElementById("uploadFile").value = this.value;
    };

    // new Clipboard('#token_api');
    $("#copy-api").click(function () {
        $(".token-api").select();
        document.execCommand('copy');
    });

    $('#register_form').validate({
        rules: {
            pass: {
                required: true,
                minlength: 3
            },
            confirm_pass: {
                required: true,
                minlength: 3,
                equalTo: "#password"
            }
        },
        messages: {
            password: {
                required: "Please enter a password",
                minlength: "Password must be at least {0} characters long",
                remote: "Password should contain: <li>At least one upper case character <li>At least one lower case character <li>At least one number <li>And may not contain any of the following: \\;-\")(&*='|$"
            },
            confirmPassword: {
                required: "Please confirm your password",
                equalTo: "The passwords do not match"
            }
        },
        onkeyup: false
    });

    $('#btn_reg').click(function () {
        console.log($('#register_form').valid());
    });
});

