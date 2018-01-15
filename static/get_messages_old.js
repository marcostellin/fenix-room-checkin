 $(document).ready(function worker() {
 
            $.getJSON("/user/ajax/messages", function(resp){
                for (var i=0; i<resp.length; i++){
                    $("#messages").notify(resp[i]["content"], "info");
                }

                if (resp.length > 0){
                    $.post("/user/ajax/messages", {read:"True"});
                }
            });

            setTimeout(worker, 5000);

});
