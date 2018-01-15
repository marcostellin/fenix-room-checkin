 $(document).ready(function worker() {
            
            var flag = false;
            $.getJSON("/user/ajax/messages", function(resp){
                    
                    flag = true;
                    alertify.alert("Message from " + resp["from"], resp["content"],
                    function (){
                       $.post("/user/ajax/messages", {read:"True"});
                       flag = false;
                       setTimeout(worker, 5000);
                    })

                
            });
            
            if (!flag){
                setTimeout(worker, 5000);
            }
           
});
