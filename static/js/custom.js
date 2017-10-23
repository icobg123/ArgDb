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
});

