 $(document).ready(function worker() {
            
            var flag = false;
            $.getJSON("/user/ajax/messages", function(resp){
                    
                    alertify.alert("Message from " + resp["from"], resp["content"],
                    function (){
                       $.post("/user/ajax/messages/"+resp["id"], {read:"True"});
                       setTimeout(worker, 5000);
                    })

                
            })
              .fail(function (){
                setTimeout(worker, 5000);
              });
           
});
