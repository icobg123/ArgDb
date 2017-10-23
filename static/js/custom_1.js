/**
 * Created by ICARA on 22-Oct-17.
 */

$(document).ready(function () {
    $("#copy_api").click(function () {
        $("#token_api").select();
        document.execCommand('copy');
    });
});

