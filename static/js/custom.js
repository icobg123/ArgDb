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

    // URL updates and the element focus is maintained
// originally found via in Update 3 on http://www.learningjquery.com/2007/10/improved-animated-scrolling-script-for-same-page-links

// filter handling for a /dir/ OR /indexordefault.page
    function filterPath(string) {
        return string
            .replace(/^\//, '')
            .replace(/(index|default).[a-zA-Z]{3,4}$/, '')
            .replace(/\/$/, '');
    }

    var locationPath = filterPath(location.pathname);
    $('a[href*="#"]').each(function () {
        var thisPath = filterPath(this.pathname) || locationPath;
        var hash = this.hash;
        if ($("#" + hash.replace(/#/, '')).length) {
            if (locationPath == thisPath && (location.hostname == this.hostname || !this.hostname) && this.hash.replace(/#/, '')) {
                var $target = $(hash), target = this.hash;
                if (target) {
                    $(this).click(function (event) {
                        event.preventDefault();
                        $('html, body').animate({scrollTop: $target.offset().top}, 1000, function () {
                            location.hash = target;
                            $target.focus();
                            if ($target.is(":focus")) { //checking if the target was focused
                                return false;
                            } else {
                                $target.attr('tabindex', '-1'); //Adding tabindex for elements not focusable
                                $target.focus(); //Setting focus
                            }
                            ;
                        });
                    });
                }
            }
        }
    });
});

