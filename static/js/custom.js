/**
 * Created by ICARA on 22-Oct-17.
 */

$(document).ready(function () {
    document.getElementById("uploadBtn").onchange = function () {
        document.getElementById("uploadFile").value = this.value;
    };
});

