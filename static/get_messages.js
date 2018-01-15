 $(document).ready(function worker() {
 
            $.getJSON("/user/ajax/messages", function(resp){
                for (var i=0; i<resp.length; i++){
                    var flag = false;
                    
                    alertify.alert("Message from " + resp[i]["from"], resp[i]["content"],
                    function (){
                       $.post("/user/ajax/messages", {read:"True"});
                       flag = true;
                    });
                    
                    while (!flag){};
                }

            });
            
            setTimeout(worker, 5000);
});
