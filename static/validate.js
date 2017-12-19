$(document).ready(function () {
    $.validator.messages.required = '';
    $('#search_fm').validate({ // initialize the plugin
        rules: {
            query: {
                required: true
            }
        },
        invalidHandler: function(event, validator){
            alert("Required Field")
        }
    });

});