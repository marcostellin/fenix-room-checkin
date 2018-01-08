 $(document).ready(function worker() {
 
            $.getJSON("/user/get_messages", function(resp){
                for (var i=0; i<resp.length; i++){
                    $("#messages").notify(resp[i]["content"], "info");
                }

                if (resp.length > 0){
                    $.post("/user/get_messages", {read:"True"});
                }
            });

            setTimeout(worker, 5000);

});
